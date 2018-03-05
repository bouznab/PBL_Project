#!/bin/bash
# This is a script to start a VLC client with automatic IP insertion
# FIRST ARGUMENT: Listening UDP-Port
if [ -z "$2" ]
then
    IP=$(hostname -I)
    IP="$(echo -e "${IP}" | tr -d '[:space:]')"
else
    IP=$2
fi


if [ -z "$1" ]
then
    PORT=5004
else
    PORT=$1
fi

vlc-wrapper rtp://${IP}:${PORT}
