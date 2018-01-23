#!/bin/bash
# This is a script to start a VLC client with automatic IP insertion
# FIRST ARGUMENT: Listening UDP-Port

IP=$(hostname -I)
IP="$(echo -e "${IP}" | tr -d '[:space:]')"

if [ -z "$1" ]
then
    PORT=5004
else
    PORT=$1
fi

vlc-wrapper rtp://${IP}:${PORT}
