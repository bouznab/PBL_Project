#!/bin/env/python

import matplotlib.pyplot as plt
import matplotlib.animation as animation

fig = plt.figure()
ax1 = fig.add_subplot(1,1,1)

slices = {"mission-critical":10023, "latency":10022, "default":10024}

def animate(i):
    graph_data = open('livestats.csv','r').read()
    lines = graph_data.split('\n')
    del lines[0]
    xs=[]
    ys1=[]
    ys2=[]
    ports = []
    port_nums = []
    for line in lines:
        if len(line) > 1:
            x,y,port = line.split(' ')
            if port not in ports:
                ports.append(port)
            y = float(y)
            port_num = slices[port]
            if port_num not in port_nums:
                port_nums.append(port_num)
            x = int(x)
            if x < 50:
                if x not in xs:
                    xs.append(x)
                if port_num == port_nums[0]:
                    ys1.append(y)
                else:
                    ys2.append(y)
            else:
                if port_num == port_nums[0]:
                    ys1.pop(0)
                    ys1.append(y)
                else:
                    ys2.pop(0)
                    ys2.append(y)

    if len(ys1) == len(ys2):
        ax1.clear()
        ax1.plot(xs, ys1, 'b-', xs,ys2, 'r-')
        plt.ylabel("Latency [ms]")
        ax1.legend(ports, loc=2)



ani = animation.FuncAnimation(fig, animate, interval=1)
plt.show()
