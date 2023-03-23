from scapy.all import *

seq = 12345
sport = 1040
dport = 80

ip_packet = IP(dst="104.16.88.120")
syn_packet = TCP(sport=sport, dport=dport, flags='S', seq=seq)

packet = ip_packet/syn_packet
synack_response = sr1(packet)

next_seq = seq + 1
my_ack = synack_response.seq + 1

ack_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)

send(ip_packet/ack_packet)

payload_packet = TCP(sport=sport, dport=dport, flags='A', seq=next_seq, ack=my_ack)
payload = "GET / HTTP/1.1\r\nHost: 104.16.88.120\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: es-ES,es;q=0.9,en;q=0.8\r\n--compressed\r\n--insecure\r\n\r\n"

reply, error = sr(ip_packet/payload_packet/payload, multi=1, timeout=1)
for r in reply:
    r[0].show2()
    r[1].show2()
