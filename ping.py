#! /usr/bin/env python

from scapy.all import *
from time import *
import sys
import netifaces 

ipToMac = {"10.0.0.1":"10:10:10:10:10:11","10.0.0.2":"10:10:10:10:10:12",
        "10.0.0.3":"10:10:10:10:10:13","10.0.0.4":"10:10:10:10:10:14"}
ipToIface={"10.0.0.1":"h1-eth2","10.0.0.2":"h2-eth2","10.0.0.3":"h3-eth2","10.0.0.4":"h4-eth2"}

def QoS_ping(host, port, iface, count=100):
    packet = Ether(dst=ipToMac[host])/IP(dst=host)/TCP(sport=port, dport=port)
    t = 0.0
    average = 0.0
    for x in range(count):
        t = 0.0
        t1=time()
        ans = srp(packet,iface=iface,verbose=0)
        t2=time()
        t+=t2-t1
        average += t
        print 'packet {} latency = {}'.format(x, t*1000)

    print'average ping = {}'.format(average/count*1000)
    #s.close()

if __name__=="__main__":
    interfaces = netifaces.interfaces()
    if len(sys.argv) <= 1:
        QoS_ping('10.0.0.3', 10022, interfaces[1])
    else: 
        QoS_ping(sys.argv[1], int(sys.argv[2]),interfaces[1])
