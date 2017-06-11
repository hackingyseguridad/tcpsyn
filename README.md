# tcpsyn con nping

# ./conexiones <puerto_TCP>
Para ver las conexiones activas

netstat -na

netstat -an | grep :80 | sort

netstat -n -p|grep SYN_REC | wc -l

netstat -n -p | grep SYN_REC | sort -u

netstat -n -p | grep SYN_REC | awk ‘{print $5}’ | awk -F: ‘{print $1}’

netstat -ntu | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -n

netstat -anp |grep ‘tcp|udp’ | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -n

netstat -ntu | grep ESTAB | awk ‘{print $5}’ | cut -d: -f1 | sort | uniq -c | sort -nr

netstat -plan|grep :80 | awk {'print $5'} | cut -d: -f 1 | sort | uniq -c

netstat -plan|grep :80|awk {‘print $5’}|cut -d: -f 1|sort|uniq -c|sort -nk 1

