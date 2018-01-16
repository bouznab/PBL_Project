#!/bin/bash
# FIRST ARGUMENT: TARGET IP
# SECOND ARGUMENT: ABSOLUTE PATH VIDEO

TARGET=$1
if [ -z "$1" ]
then
    TARGET='10.0.0.3'
else
    TARGET=$1
fi
if [ -z "$2" ]
then
    VIDEO='/home/virt/host_share/PBL_Project/example.avi'
else
    VIDEO=$2
fi

FIRST='#rtp{access=udp,mux=ts,dst='
LAST=',port=5004}'

vlc-wrapper -vvv file://${VIDEO} --sout ${FIRST}${TARGET}${LAST} :sout-all
