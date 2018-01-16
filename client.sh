#!/bin/bash
# This is a script to start a VLC client with automatic IP insertion

IP=$(hostname -I)

vlc-wrapper rtp://${IP}:5004
