from scapy.all import *

import sys
from multiprocessing import Pool


def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()


def check_pair(conf):
    ip, iface, port = conf
    # debug("Scanning: {}:{}".format(ip, port))
    syn = IP(dst=ip)/TCP(dport=port, flags="S")
    syn_ack = sr1(syn, timeout=10, verbose=0)
    if syn_ack.getlayer(TCP).flags == "SA":
        print("{}:{}".format(ip, port))
    else:
        # debug("Closed: {}:{}".format(ip, port))
        return


if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])

    # SYN scan
    configs = map(lambda x: (ip_addr, conf.iface, x), range(1, 1025))
    with Pool(32) as p:
        p.map(check_pair, configs)
