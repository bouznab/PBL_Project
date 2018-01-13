from time import sleep
from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.node import RemoteController


net = Mininet(controller=RemoteController)

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

c0 = net.addController('c0', port=6633)

#adding links
net.addLink(h1, s1)
net.addLink(h2, s2)
net.addLink(h3, s3)
net.addLink(h4, s4)
net.addLink(s1, s4)
net.addLink(s1, s2)
net.addLink(s2, s3)
net.addLink(s3, s4)

net.build()
c0.start()
s1.start([c0])
s2.start([c0])
s3.start([c0])
s4.start([c0])
net.start()

result = c0.cmd("bash -c \"ryu-manager --verbose simple_switch_stp_13.py > /home/virt/host_share/PBL_Project/ryu.out 2>&1 &\"")
sleep(2)

#net.pingAll()
#sleep(2)
#net.pingAll()

CLI(net)

c0.cmd('kill %while')
net.stop()
