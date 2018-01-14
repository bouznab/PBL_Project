from mininet.net import Mininet
from mininet.node import Host
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink

net = Mininet(link=TCLink)

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

c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',
                       port=6633)

#adding links
net.addLink(h1, s1, bw=1, delay='1ms')
net.addLink(h2, s2, bw=1, delay='1ms')
net.addLink(h3, s3, bw=1, delay='1ms')
net.addLink(h4, s4, bw=1, delay='1ms')
net.addLink(s1, s4, bw=1, delay='1ms')
net.addLink(s1, s2, bw=1, delay='1ms') 
net.addLink(s2, s3, bw=1, delay='1ms')
net.addLink(s3, s4, bw=1, delay='1ms')

net.start()
CLI(net)
net.stop()
