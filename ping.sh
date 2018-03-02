#!/bin/bash
# FIRST ARGUMENT - time: how many pings are measured, time = 0 -> infinite times
# SECOND ARGUMENT - ip address of destination host 
# THIRD ARGUMENT - SIXTH ARGUMENT - ports latency measurement, up to 4 ports, at least 1 port 

if [ -z "$1" ]
then
    TIME=100
else
    TIME=$1
fi
if [ -z "$2" ]
then
    TARGET='10.0.0.4'
else
    TARGET=$2
fi
if [ -z "$3" ]
then
    PORT1=10022
else 
    PORT1=$3
fi
if [ -z "$4" ]
then
    PORT2=''
else 
    PORT2=$4
fi
if [ -z "$5" ]
then
    PORT3=''
else 
    PORT3=$5
fi
if [ -z "$6" ]
then
    PORT4=''
else 
    PORT4=$6
fi

echo ${PORT4}

echo "ping latency port" > stats.csv
python ping.py -t ${TIME} -i ${TARGET} -p ${PORT1} ${PORT2} ${PORT3} ${PORT4} 2>> stats.csv &

echo waiting
wait
sed -i '2d' stats.csv
Rscript pinggraphs.R
echo done
