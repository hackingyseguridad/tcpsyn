# tcpsyn con nping

Ver conexiones activas por ejemplo puerto 80:

netstat -plan|grep :80 | awk {'print $5'} | cut -d: -f 1 | sort | uniq -c | sort -n

