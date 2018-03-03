#!/bin/bash
# FIRST ARGUMENT: target PORT
# SECOND ARGUMENT: time interval


PORT=$1
if [ -z "$1" ]
then
    PORT='10023'
else
    PORT=$1
fi

if [ -z "$2" ]
then
    INTERVAL=5
else
    INTERVAL=$2
fi

iperf3 -s -p ${PORT} -i ${INTERVAL} 
