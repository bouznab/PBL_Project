#! /usr/bin/env python

from scapy.all import *
from time import *
import sys
import netifaces 

ipToMac = {"10.0.0.1":"10:10:10:10:10:11","10.0.0.2":"10:10:10:10:10:12",
        "10.0.0.3":"10:10:10:10:10:13","10.0.0.4":"10:10:10:10:10:14"}

def QoS_ping(host, iface, port =10022, count=100):
    packet = Ether(dst=ipToMac[host])/IP(dst=host)/TCP(sport=port, dport=port,flags="S")
    t = 0.0
    average = 0.0
    for x in range(count):
        t = 0.0
        t1=time()
        ans = srp(packet,iface=iface,verbose=0)
        t2=time()
        t+=t2-t1
        average += t
        s = '{} {}'.format(x, t*1000)
        print(s)


if __name__=="__main__":
    interfaces = netifaces.interfaces()
    if len(sys.argv) <= 1:
        QoS_ping('10.0.0.3', interfaces[1])
    elif len(sys.argv) ==2: 
        QoS_ping(sys.argv[1],interfaces[1])
    else:
        QoS_ping(sys.argv[1], interfaces[1], int(sys.argv[2]))
