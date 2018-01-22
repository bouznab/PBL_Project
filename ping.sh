#!/bin/bash

if [ -z "$1" ]
then
    TARGET='10.0.0.4'
else
    TARGET=$1
fi
if [ -z "$2" ]
then
    PORT=10022
else
    PORT=$2
fi

echo "ping latency" > stats.csv
python /media/sf_PBL-Project/ping.py ${TARGET} ${PORT} >> stats.csv
Rscript /media/sf_PBL-Project/graphs.R 
