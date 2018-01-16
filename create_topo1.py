#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel


class mytopo(Topo):
    def __init__(self, n=2, **opts):
        Topo.__init__(self, **opts)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
	    h3 = self.addHost('h3')
	    h4 = self.addHost('h4')
        s = []
        for i in range(4):
            switch = self.addSwitch('s%s' % i+1,protocols="Openflow13")
            s.append(switch)
    for h in self.hosts:
		print "disable ipv6"
		h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
	for sw in self.switches:
		print("disable ipv6 for switch", sw)
		sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',     port=6633)
        # print s
        self.addLink(h1, s[0])
        self.addLink(h2, s[1])
	    self.addLink(h3, s[2])
	    self.addLink(h4, s[3])

        self.addLink(s[1], s[2])
        self.addLink(s[2], s[3])

        self.addLink(s[1], s[0])
        self.addLink(s[0], s[3])

class SingleSwitch(Topo):
    "Single switch connected to n hosts."

    def __init__(self, n=4, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

            # linkopts = dict(bw=10, delay='5ms', loss=10, max_queue_size=1000, use_htb=True)
            # (or you can use brace syntax: linkopts = {'bw':10, 'delay':'5ms', ... } )
            # self.addLink(node1, node2, **linkopts)


def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitch(n=4)
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()


topos = {'SingleSwitch': SingleSwitch, 'mytopo':mytopo }
tests = {'mytest': simpleTest}

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
