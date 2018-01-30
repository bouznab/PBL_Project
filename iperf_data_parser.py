#!/bin/env/python

raw_data = open('iperf_stats.csv','r').read()
lines = raw_data.split('\n')
del lines[0:3]
lines.pop()
file = open("iperf_plot.csv", "w")
file.write("time throughput retry\n")
for line in lines:
    data= []
    words = line.split(' ')
    del words[0:1]
    for word in words:
        if len(word) >= 1:
            data.append(word)

    time = data[1].split('-')
    s = "{} {} {}\n".format(time[0], data[5], data[7])
    file.write(s)
