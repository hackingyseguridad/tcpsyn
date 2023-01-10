#!/bin/bash
# script monitorea, numero de conexiones establecidas, % uso de CPU y de Memoria
# (c) hacking y seguridad .com 2023

while :
do
  cpuUsage=$(top -bn1 | awk '/Cpu/ { print $2}')
  memUsage=$(free -m | awk '/Mem/{print $3}')
  echo "Uso de CPU: $cpuUsage%"
  echo "Uso de Memoria: $memUsage MB"
  echo "Conexiones: " && netstat -plan|grep :$1 | awk {'print $5'} | cut -d: -f 1 | sort | uniq -c
  sleep 3
  echo "### www.hackingyseguridad.com ###"
done

