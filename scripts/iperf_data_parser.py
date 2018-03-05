#!/bin/env/python

from sys import argv 

slices = {10022:"latency", 10023:"mission-critical"}

file = open("iperf_plot1.csv", "w")
file.write("time throughput retry port\n")

argv.pop(0)
for stats in argv:
    raw_data = open(stats, 'r').read()
    _, _, parts = stats.split('_')
    port, _ = parts.split('.')
    if int(port) in slices:
        portname = slices[int(port)]
    else:
        portname = "default"
    lines = raw_data.split('\n')
    del lines[0:3]
    for _ in range(7):
        lines.pop()
    for line in lines:
        data= []
        words = line.split(' ')
        del words[0:1]
        for word in words:
            if len(word) >= 1:
                data.append(word)

        time = data[1].split('-')
        s = "{} {} {} {}\n".format(time[0], data[5], data[7], portname)

        file.write(s)
