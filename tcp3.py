# sport = random.randint(1024,65535)
dport = 80
# ip_src = '192.168.23.131'
ip_dst = '81.17.241.142'

# SYN     
ip=IP(src=ip_src, dst=ip_dst)
SYN=TCP(sport=sport, dport=dport, flags='S', seq=1000)
SYNACK=sr1(ip/SYN)

# ACK          
ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)

# GET request
req =  "GET / HTTP/1.1\r\n"
req += "Host: " + ip_dst + "\r\n"
# Other headers ...
req += "\r\n"

DATA = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)/req
ANS = sr1(DATA) # this is probably going to be only an ACK segment, next one should be your HTTP response
