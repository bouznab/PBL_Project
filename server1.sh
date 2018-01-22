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
    AUDEO='/home/fengchao/PBL_Project/music.mp3'
else
    AUDEO=$2
fi

FIRST='#rtp{access=udp,mux=ts,dst='
LAST=',port=10023}'

vlc-wrapper -vvv file://${AUDEO} --sout ${FIRST}${TARGET}${LAST} :sout-all
~                                                                               
"~/PBL_Project/server1.sh" 22L, 377C                                           
