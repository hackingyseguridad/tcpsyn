#!/bin/bash
# TEST DE STRESS TCPSYN CON WGET
# Antonio Taboada 30/12/2016
# Aplicar permisos con chmod *x tcpsynwget.sh
# Ejecutar ./tcpsynwget.sh
# Para parar Control + C

while true; do
        wget -O /dev/null web.hackingyseguridad.com
done