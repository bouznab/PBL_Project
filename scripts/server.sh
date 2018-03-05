#!/bin/bash
# FIRST ARGUMENT: TARGET IP
# SECOND ARGUMENT: TARGET UDP-Port
# THIRD ARGUMENT: ABSOLUTE PATH FILE

if [ -z "$1" ]
then
    TARGET='10.0.0.3'
else
    TARGET=$1
fi
if [ -z "$2" ]
then
    PORT=5004
else
    PORT=$2
fi
if [ -z "$3" ]
then
    FILE='/home/virt/host_share/PBL_Project/example.avi'
else
    FILE=$3
fi

CONF="#rtp{access=udp,mux=ts,dst=${TARGET},port=${PORT}}"


vlc-wrapper -vvv file://${FILE} --sout ${CONF} :sout-all
