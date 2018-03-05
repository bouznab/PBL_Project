# Problem Based Learning Project WS 17/18

## Measuring and Plotting 
In the subdirectory scripts are several shell- and pythonscripts to help measure and plot the latency of network packets and throughput and losses of iperf3 clients and servers. 
The commands have to be executed on hosts in the mininet topology, except two specifc commands as stated below. 

#### Latency
For latency you have to options: 
1. measure a certain number of pings on different slices and plot them afterwards:
```
./scripts/ping.sh <number_of_pings> <ip_address_of_destination_host> <port1> ... <port4> 
```
The plot is saved under the name `ping.svg`. 
2. show a realtime plot of two different slices:
```
./scripts/liveping.sh <ip_address_of_destination> <1.port> <2.port>
```
and 
```
python live.py
```
to start the plot. This command does not have to be executed in the mininet VM. 
The realtime plot has to be turned off manually by just closing the plotting window and stop `liveping.sh` with `CTRL+C` or `CTRL+Z`.

#### Iperf3 measurements
For throughput and loss measurements you need a client and a server.
* Start a server:
```
./scripts/iperf-server.sh <listening_port> <time_interval> 
``` 
* Start a client with:
```
./iperf-client.sh <ip_address_of_destination> <port> <time_interval> <time>
``` 
After successfully running an iperf metering, there should be a csv-file in your working directory with the name: `iperf_client_<port>.csv`.
You can easily start multiple measurements at the same time. 
To plot graphs you have to run the command:
```
./plot_iperf.sh <csv_file_1> <csv_file_2> ... <csv_file_n> 
``` 
The script generate two plots with the names `throughput.svg` and `retry.svg` in the working directory.

#### Video streams 
In order to start a video stream you have to start a server and to actually watch the stream a client as well.
* Start a video stream server:
```
./scripts/server.sh <ip_address_of_client> <port> <absolute_path_to_video_file>
```
* Start a client:
```
./scripts/client.sh <port>
``` 
The video streaming is working with unicast and also with broadcast and mulitcast, as described in the report.

## Required software
* a VM for mininet (we used Ubuntu 16.04.)
* Python (version 2.7.12)
* native installation of Mininet (version 2.2.2)
* ryu (version 4.20)
* Open vSwitch (version 2.5.2)
* scapy (version 2.2.0)
* matplotlib (version 2.1.2) 
* netifaces (version 0.10.6)
* iperf3 (version 3.4+)
* R (version 3.2.3) 
* ... 
