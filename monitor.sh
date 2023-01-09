#!/bin/bash
# este script monitorea el uso de CPU y Memeoria

while :
do
  cpuUsage=$(top -bn1 | awk '/Cpu/ { print $2}')
  memUsage=$(free -m | awk '/Mem/{print $3}')
  echo "CPU Usage: $cpuUsage%"
  echo "Memory Usage: $memUsage MB"
  sleep 3
done
