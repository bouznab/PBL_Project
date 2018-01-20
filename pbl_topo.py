#!/usr/bin/env python
# -*- coding: utf-8 -*-

from time import sleep
from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.node import OVSSwitch

"""
    H1 ²---² S1 ⁴----------³ S4 ²---² H4
             ³                ⁴
             |                |
             |                |
             ⁴                ³
    H2 ²---² S2 ³----------⁴ S3 ²---² H3

    The little numbers are the switch ports.
    """

net = Mininet(link=TCLink, controller=RemoteController, switch=OVSSwitch)

#hosts
h1 = net.addHost('h1')
h2 = net.addHost('h2')
h3 = net.addHost('h3')
h4 = net.addHost('h4')

#Switches
s1 = net.addSwitch('s1', protocols="OpenFlow13")
s2 = net.addSwitch('s2', protocols="OpenFlow13")
s3 = net.addSwitch('s3', protocols="OpenFlow13")
s4 = net.addSwitch('s4', protocols="OpenFlow13")

c0 = net.addController('c0', ip='127.0.0.1', port=6633)

#adding links
net.addLink(h1, s1, port1=2, port2=2)
net.addLink(h2, s2, port1=2, port2=2)
net.addLink(h3, s3, port1=2, port2=2)
net.addLink(h4, s4, port1=2, port2=2)
net.addLink(s1, s2, port1=3, port2=4)
net.addLink(s2, s3, port1=3, port2=4)
net.addLink(s3, s4, port1=3, port2=4)
net.addLink(s4, s1, port1=3, port2=4)

net.build()
# c0.start()
# s1.start([c0])
# s2.start([c0])
# s3.start([c0])
# s4.start([c0])
net.start()
h1.setMAC("10:10:10:10:10:11")
h2.setMAC("10:10:10:10:10:12")
h3.setMAC("10:10:10:10:10:13")
h4.setMAC("10:10:10:10:10:14")
for h in [h1, h2, h3, h4]:
    h.setARP(ip="10.0.0.1", mac="10:10:10:10:10:11")
    h.setARP(ip="10.0.0.2", mac="10:10:10:10:10:12")
    h.setARP(ip="10.0.0.3", mac="10:10:10:10:10:13")
    h.setARP(ip="10.0.0.4", mac="10:10:10:10:10:14")

for h in net.hosts:
    #print "disable ipv6"
    h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

for sw in net.switches:
    #print "disable ipv6"
    sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


################################ Change this line so that slicing.py (or whatever controller) can be imported by ryu-manager and adjust the log-file ###########
#result = c0.cmd("bash -c \"ryu-manager graph_controller.py>&2 2>/home/virt/host_share/PBL_Project/ryu.out &\"")

## Configure Priority queues in ovs-switch
qos_id = s1.cmd('ovs-vsctl create qos type=linux-htb other-config:max-rate=800000 \
                queues=0=@be,1=@af,2=@ef \
                -- --id=@be create queue other-config:priority=1 \
                -- --id=@af create queue other-config:priority=50 other-config:min-rate=1000 \
                -- --id=@ef create queue other-config:priority=150 other-config:min-rate=100000').splitlines()[0]
for link in net.links:
    print("link: {} <-> {}".format(link.intf1.name, link.intf2.name))
    s1.cmd('ovs-vsctl set Port %s qos=%s' % (link.intf1.name, qos_id))
    s1.cmd('ovs-vsctl set Port %s qos=%s' % (link.intf2.name, qos_id))

CLI(net)

for sw in net.switches:
    sw.cmd('ovs-vsctl -- --all destroy QoS -- --all destroy Queue')

c0.cmd('kill %while')
net.stop()
