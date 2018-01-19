#! /usr/bin/env python

from scapy.all import *
from time import *
import sys

def QoS_ping(host, port, count=100):
    packet = IP(dst=host)/TCP(sport=port, dport=port)
    t = 0.0
    average = 0.0
    s = conf.L3socket(iface='h1-eth2')
    for x in range(count):
        t = 0.0
        t1=time()
        ans=s.sr1(packet, verbose=0)
        rx=ans[0][1]
        tx=ans[0][0]
        delta = rx.time -tx.sent_time
        t2=time()
        t+=t2-t1
        average += t
        print 'packet {} latency = {}'.format(x, t*1000)

    print'average ping = {}'.format(average/count*1000)
    s.close()

if __name__=="__main__":
    if len(sys.argv) < 1:
        QoS_ping('10.0.0.3', 10022)
    else: 
        QoS_ping(sys.argv[1], int(sys.argv[2]))
