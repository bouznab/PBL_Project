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
python ping.py ${TARGET} ${PORT} >> stats.csv &
echo "ping latency" > stats2.csv
python ping.py ${TARGET} 10024 >> stats2.csv &

echo waiting
wait
Rscript graphs.R
echo done
