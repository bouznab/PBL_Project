#! /usr/bin/env python

from scapy.all import *
from time import *
import sys
import threading
import netifaces 

ipToMac = {"10.0.0.1":"10:10:10:10:10:11","10.0.0.2":"10:10:10:10:10:12",
        "10.0.0.3":"10:10:10:10:10:13","10.0.0.4":"10:10:10:10:10:14"}


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
    ans,unans = srp(packet,iface=iface,timeout=15, verbose=0)
    t2=time()
    t+=t2-t1
    s = '{} {}'.format(t*1000, port)
    return s


if __name__=="__main__":
    threadLock = threading.Lock()
    threads = []
    if len(sys.argv) < 2:
        host = "10.0.0.4"
        port2 = 10022
        port1 = 10024
    elif len(sys.argv) ==2: 
        host = sys.argv[1]
        port1 = 10022
    elif len(sys.argv) ==3:
        host = sys.argv[1]
        port1 = int(sys.argv[2])
        port2 = 10024
    else:
        host = sys.argv[1]
        port1 = int(sys.argv[2])
        port2 = int(sys.argv[3])


    for x in range(100):
        thread1 = pingThread(1, "thread-1", host, port1, x)
        thread2 = pingThread(2, "thread-2", host, port2, x)

        thread1.start()
        thread2.start()

        threads.append(thread1)
        threads.append(thread2)

        for t in threads:
            t.join()
