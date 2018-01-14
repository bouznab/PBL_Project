from time import sleep
from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import TCLink

net = Mininet(link=TCLink, controller=RemoteController)

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

for h in net.hosts:
    print "disable ipv6"
    h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

for sw in net.switches:
    print("disable ipv6 for switch", sw)
    sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

c0 = net.addController('c0', port=6633)

#adding links
linkopts =  dict(bw=400, delay='0.5ms', loss=0)
linkopts_reliable = dict(bw=100, delay='5ms', loss=0)
linkopts_video = dict(bw=200, delay='20ms', loss=0) #FIXME loss=2
linkopts_latency = dict(bw=300, delay='0.5ms', loss=0) #FIXME  bw=10 and loss=2
net.addLink(h1, s1, port1=2, port2=2, **linkopts)
net.addLink(h2, s2, port1=2, port2=2, **linkopts)
net.addLink(h3, s3, port1=2, port2=2, **linkopts)
net.addLink(h4, s4, port1=2, port2=2, **linkopts)
net.addLink(s1, s2, port1=3, port2=4, **linkopts_latency)
net.addLink(s2, s3, port1=3, port2=4, **linkopts_latency)
net.addLink(s3, s4, port1=3, port2=4, **linkopts_video)
net.addLink(s4, s1, port1=3, port2=4, **linkopts_video)

net.build()
c0.start()
s1.start([c0])
s2.start([c0])
s3.start([c0])
s4.start([c0])
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

################################ Change this line so that hardcoded.py can be imported by ryu-manager and adjust the log-file ###########
result = c0.cmd("bash -c \"ryu-manager hardcoded.py>&2 2>/home/virt/host_share/PBL_Project/ryu.out &\"")
print(result)
sleep(2)

#net.pingAll()
#sleep(2)
#net.pingAll()

CLI(net)

c0.cmd('kill %while')
net.stop()
