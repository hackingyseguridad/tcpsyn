#!/bin/sh
# tcpsyn
# tcpsyn.sh Programado en shell. requeiere tener instalado nping. apt-get install nmap
# boton derecho para dar permisos del ejecucion o desde consola teclemaos: chmod 777 tcpsyn.sh
# se ejecuta en consola ./tcpsyn.sh
# Antonio Taboada
# 3 Sept 2016
nping --tcp-connect -rate=90000 -c 900000 -q 192.168.1.252