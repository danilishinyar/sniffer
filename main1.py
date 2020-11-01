import scapy.all as scapy
import subprocess
import re
from scapy.layers import http


def get_iface_and_ip():
	iface_and_ip = {}
	avaliable_ifaces = re.findall(r'\w+: ',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
	for i in range(len(avaliable_ifaces)):
		if avaliable_ifaces[i][0]=='n':
			avaliable_ifaces[i] = avaliable_ifaces[i][1:]
	avaliable_ip = re.findall(r'inet\s\d+.\d+.\d+.\d+',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
	for i in range(len(avaliable_ifaces)):
		iface_and_ip.update({avaliable_ifaces[i].replace(': ',''):avaliable_ip[i].replace('inet ', '')})
	return iface_and_ip


def sniff(iface,filter):
	if filter == 'http':
		scapy.sniff(iface=iface, prn=callback_http1, store=False)
	elif filter == 'dns':
		scapy.sniff(iface=iface, prn=callback_dns1, store=False)
	else:
		scapy.sniff(iface=iface, filter=filter, prn=callback, store=False)


def callback(pkt):
	global host_ip
	if pkt.haslayer('TCP'):
		if host_ip == pkt['IP'].src:
			print('TCP OUT:'+' '+'SRC-MAC:'+str(pkt.src)+' '+'SRC-IP:'+str(pkt['IP'].src)+' '+'SRC-PORT:'+str(pkt.sport)+' '+'\n'+'DST-MAC:'+str(pkt.dst)+' '+'DST-IP:'+str(pkt['IP'].dst)+' '+'DST-PORT:'+str(pkt.dport)+' '+'FLAGS:'+str(pkt['TCP'].flags)+'\r\n')
		else:
			print('TCP IN:'+' '+'SRC-MAC:'+str(pkt.src)+' '+'SRC-IP:'+str(pkt['IP'].src)+' '+'SRC-PORT:'+str(pkt.sport)+' '+'\n'+'DST-MAC:'+str(pkt.dst)+' '+'DST-IP:'+str(pkt['IP'].dst)+' '+'DST-PORT:'+str(pkt.dport)+' '+'FLAGS:'+str(pkt['TCP'].flags)+'\r\n')
	elif pkt.haslayer('UDP'):
		if host_ip == pkt['IP'].src:
			print('UDP OUT:'+' '+'SRC-MAC:'+str(pkt.src)+' '+'SRC-IP:'+str(pkt['IP'].src)+' '+'SRC-PORT:'+str(pkt.sport)+' '+'\n'+'DST-MAC:'+str(pkt.dst)+' '+'DST-IP:'+str(pkt['IP'].dst)+' '+'DST-PORT:'+str(pkt.dport)+'\r\n')
		else:
			print('UDP IN:'+' '+'SRC-MAC:'+str(pkt.src)+' '+'SRC-IP:'+str(pkt['IP'].src)+' '+'SRC-PORT:'+str(pkt.sport)+' '+'\n'+'DST-MAC:'+str(pkt.dst)+' '+'DST-IP:'+str(pkt['IP'].dst)+' '+'DST-PORT:'+str(pkt.dport)+'\r\n')
	elif pkt.haslayer('ARP'):
		if str(pkt['ARP'].op)=='1':
			print('ARP-REQUEST:'+' '+'SRC-MAC:'+str(pkt['ARP'].hwsrc)+' SRC-IP:'+str(pkt['ARP'].psrc)+' DST-MAC:'+str(pkt['ARP'].hwdst)+' DST-IP:'+str(pkt['ARP'].pdst)+'\r\n')
		else:
			print('ARP-RESPONSE:'+' '+'SRC-MAC:'+str(pkt['ARP'].hwsrc)+' SRC-IP:'+str(pkt['ARP'].psrc)+' DST-MAC:'+str(pkt['ARP'].hwdst)+' DST-IP:'+str(pkt['ARP'].pdst)+'\r\n')


def callback_dns1(pkt):
	 if pkt.haslayer('DNSRR'):
		 print('DNS-RESPONSE:'+pkt['DNSRR'].rrname.decode(encoding='utf-8')+' RESPONSE:'+str(pkt['DNSRR'].rdata))
	 elif pkt.haslayer('DNSQR'):
		 print('DNS-REQUEST:'+pkt['DNSQR'].qname.decode(encoding='utf-8'))


def callback_http1(pkt):
	if pkt.haslayer(http.HTTPRequest):
		h = bytes(pkt[http.HTTPRequest])
		return h.decode(encoding='utf-8')


print('Choose one of avaliable network interfaces:',*get_iface_and_ip(), sep='\n')
iface = str(input())
host_ip = get_iface_and_ip()[iface]
print('Choose filter (http, arp, tcp, udp, dns for e.g):')
filter=str(input())
sniff(iface,filter)
