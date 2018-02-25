#!/bin/bash
# FIRST ARGUMENT IP address of server
# SECOND ARGUMENT PORT
# THIRD AGRUMENT time interval
# FORTH ARGUMENT time

ClientIP=$(hostname -I)
ClientIP="$(echo  "${ClientIP}" | tr -d '[:space:]')"

if [ -z "$1" ]
then
    IP='10.0.0.4'
else
    IP=$1
fi
if [ -z "$1" ]
then
    PORT='10023'
else
    PORT=$2
fi
if [ -z "$3" ]
then
    INTERVAL=5
else
    INTERVAL=$3
fi
if [ -z "$4" ]
then
    TIME=150
else
    TIME=$4
fi

echo "starting iperf3 client"

iperf3 -c ${IP} -p ${PORT} -t ${TIME} -i ${INTERVAL} -w 1M --cport ${PORT} -B ${ClientIP} > iperf_stats_${PORT}.csv
echo "ready to plot"
# python iperf_data_parser.py iperf_stats_${PORT}.csv
# Rscript iperfgraphs.R

