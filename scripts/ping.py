#!/usr/bin/env/python

from scapy.all import *
from time import *
import sys
import argparse
import threading
import netifaces

ipToMac = {"10.0.0.1":"10:10:10:10:10:11","10.0.0.2":"10:10:10:10:10:12",
        "10.0.0.3":"10:10:10:10:10:13","10.0.0.4":"10:10:10:10:10:14", "10.255.255.255":"ff:ff:ff:ff:ff:ff"}
slices = {10022:"latency", 10023:"mission-critical"}


class pingThread(threading.Thread):
    def __init__(self, threadID, name, host, port,counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.host = host
        self.port = port
        self.counter = counter

    def run(self):
        interfaces = netifaces.interfaces()
        threadLock.acquire(1)
        string = ping(self.host, interfaces[1], self.port)
        string = "{} {}\n".format(self.counter, string)
        sys.stderr.write(string)
        threadLock.release()

def ping(host, iface, port =10022):
    packet = Ether(dst=ipToMac[host])/IP(dst=host)/TCP(sport=port, dport=port,flags="S")
    t = 0.0
    t1=time()
    ans,unans = srp(packet,iface=iface,timeout=6, verbose=0)
    t2=time()
    t+=t2-t1
    if port in slices:
        s = '{} {}'.format(t*1000, slices[port])
    else:
        s = '{} {}'.format(t*1000, "default")
    return s


if __name__=="__main__":
    parser = argparse.ArgumentParser(prog='ping')
    parser.add_argument('-i', '--ipaddress', help="ip address of destination", nargs='+')
    parser.add_argument('-p', '--ports', help="first port to measure", required=True, nargs='+')
    parser.add_argument('-t', '--time', help="how many times the prog should ping", required=True)
    args = parser.parse_args()

    threadLock = threading.Lock()
    num_threads = len(args.ports)
    host = "10.0.0.4"
    if args.ipaddress != None:
        host=args.ipaddress[0]

    ports = []
    for port in args.ports:
        ports.append(int(port))

    if int(args.time) == 0:
        x = 0
        while True:
            threads = []
            for i in range(num_threads):
                t = pingThread(i, "thread", host, ports[i], x)
                threads.append(t)

            for t in threads:
                t.start()

            for t in threads:
                t.join()
            x += 1
    else:
        for x in range(int(args.time)):
            threads = []
            for i in range(num_threads):
                t = pingThread(i, "thread", host, ports[i], x)
                threads.append(t)

            for t in threads:
                t.start()

            for t in threads:
                t.join()
