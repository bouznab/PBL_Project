#!/bin/env python

import matplotlib.pyplot as plt 
import matplotlib.animation as animation

fig = plt.figure()
ax1 = fig.add_subplot(1,1,1)

def animate(i):
    graph_data = open('stats.csv','r').read()
    lines = graph_data.split('\n')
    del lines[0]
    xs=[]
    ys1=[]
    ys2=[]
    for line in lines:
        if len(line) > 1:
            x,y,port = line.split(' ')
            y = float(y)
            port = int(port)
            if int(x) < 25:
                if x not in xs:
                    xs.append(x)
                if port == 10022:
                    ys1.append(y)
                else:
                    ys2.append(y)
            else:
                if port == 10022:
                    ys1.pop(0)
                    ys1.append(y)
                else:
                    ys2.pop(0)
                    ys2.append(y)

    if len(ys1) == len(ys2):
        ax1.clear()
        ax1.plot(xs, ys1, 'b-', xs,ys2, 'r-')
    


ani = animation.FuncAnimation(fig, animate, interval=1)
plt.show()
