#!/bin/sh
# tcpsyn lento para server web http
# tcpsyn.sh. Requeiere tener instalado nping. 
# apt-get install nmap
# chmod 777 tcpsyn.sh
# ./tcpsyn.sh
# Antonio Taboada
# 13 Nov 2016
nping --tcp-connect -rate=3 -c 90000000 -q 192.168.1.252
