#!/bin/bash

if [ -z "$1" ]
then
    TARGET='10.0.0.4'
else
    TARGET=$1
fi
if [ -z "$2" ]
then
    PORT1=10022
else
    PORT1=$2
fi
if [ -z "$3" ]
then
    PORT2=10024
else 
    PORT2=$3
fi


echo "ping latency port" > stats.csv
python ping.py ${TARGET} ${PORT1} ${PORT2} >> stats.csv &

echo waiting
wait
sed -i '2d' stats.csv
Rscript graphs.R
echo done
