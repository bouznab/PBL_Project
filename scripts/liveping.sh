#!/bin/bash

#FIRST ARGUMENT ip address of destination hosts
#SECOND ARGUMENT first port/slice to measure
#THIRD ARGUMENT second port/slice to measure

if [ -z "$1" ]
then
    IP='10.0.0.3'
else
    IP=$1
fi
if [ -z "$2" ]
then
    PORT1=10023
else
    PORT1=$2
fi
if [ -z "$3" ]
then
    PORT2=10024
else
    PORT2=$3
fi

python scripts/ping.py -t 0 -i ${IP} -p ${PORT1} ${PORT2} 2> livestats.csv

rm livestats.csv
