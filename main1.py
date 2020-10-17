import scapy.all as scapy
import subprocess
import re
from scapy.layers import http

def choose_iface():
	avaliable_ifaces = re.findall(r'\d+\:\ \w+\:',str(subprocess.run(['ip', 'link'], stdout = subprocess.PIPE)))
	for i in range(len(avaliable_ifaces)):
		avaliable_ifaces[i] = avaliable_ifaces[i].replace(":", "")
	return avaliable_ifaces


def sniff(iface,filter):
	if filter == 'http':
		scapy.sniff(iface=iface, prn=packet_http, store=False)
	else:
		scapy.sniff(iface=iface, filter=filter, prn=lambda x:x.show, store=False)


def packet_http(packet):
	if filter == 'http':
		if packet.haslayer(http.HTTPRequest):
			print(packet.show)


print('Choose one of avaliable network interfaces:',*choose_iface(), sep='\n')
iface = str(input())
print('Choose filter (http, arp, tcp, udp avaliable):')
filter=str(input())
sniff(iface,filter)
