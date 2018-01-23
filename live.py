#!/bin/env python

import matplotlib.pyplot as plt 
import matplotlib.animation as animation
import numpy as np

fig = plt.figure()
ax1 = fig.add_subplot(1,1,1)

def animate(i):
    graph_data = open('stats.csv','r').read()
    lines = graph_data.split('\n')
    del lines[0]
    xs=[]
    ys=[]
    for line in lines:
        if len(line) > 1:
            x,y = line.split(' ')
            if int(x) < 25:
                xs.append(x)
                ys.append(y)
                print "{} {}".format(x,y)
            else:
                ys.pop(0)
                ys.append(y)
    ax1.clear()
    ax1.plot(xs, ys)

ani = animation.FuncAnimation(fig, animate, interval=1)
plt.show()
