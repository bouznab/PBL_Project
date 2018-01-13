from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.node import RemoteController

net = Mininet()

#hosts

h1 = net.addHost('h1')
h2 = net.addHost('h2')
h3 = net.addHost('h3')
h4 = net.addHost('h4')

#Switches
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')

c0 = net.addController('c0', controller=RemoteController)

#adding links
net.addLink(h1, s1)
net.addLink(h2, s2)
net.addLink(h3, s3)
net.addLink(h4, s4)
net.addLink(s1, s4)
net.addLink(s1, s2)
net.addLink(s2, s3)
net.addLink(s3, s4)

net.start()
CLI(net)
net.stop()
