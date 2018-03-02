#!/bin/env/python

from sys import argv 

file = open("iperf_plot1.csv", "w")
_, type, _ = argv[1].split('_')
if type == "client":
    file.write("time throughput retry port\n")
else:
    file.write("time throughput port\n")

argv.pop(0)
for stats in argv:
    raw_data = open(stats, 'r').read()
    _, _, parts = stats.split('_')
    port, _ = parts.split('.')
    lines = raw_data.split('\n')
    if type == "client":
        del lines[0:3]
    else:
        del lines[0:6]
    lines.pop()
    for line in lines:
        data= []
        words = line.split(' ')
        del words[0:1]
        for word in words:
            if len(word) >= 1:
                data.append(word)

        print(data)
        time = data[1].split('-')
        print(len(data))
        if type == "client":
            s = "{} {} {} {}\n".format(time[0], data[5], data[7], port)
        else:
            s = "{} {}  {}\n".format(time[0], data[5], port)

        file.write(s)
