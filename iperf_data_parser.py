#!/bin/env/python

from sys import argv 

file = open("iperf_plot.csv", "w")
file.write("time throughput retry port\n")

argv.pop(0)
for stats in argv:
    raw_data = open(stats, 'r').read()
    _,_, parts = stats.split('_')
    port, _ = parts.split('.')
    lines = raw_data.split('\n')
    del lines[0:3]
    lines.pop()
    for line in lines:
        data= []
        words = line.split(' ')
        del words[0:1]
        for word in words:
            if len(word) >= 1:
                data.append(word)

        time = data[1].split('-')
        s = "{} {} {} {}\n".format(time[0], data[5], data[7], port)
        file.write(s)
