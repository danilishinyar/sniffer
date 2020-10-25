import scapy.all as scapy
import subprocess
import re


def choose_iface_ip():
    choose_ip = []
    avaliable_ifaces = re.findall(r'\w+: ',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
    avaliable_ip = re.findall(r'inet\s\d{3}.\d+.\d+.',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
    for i in range(len(avaliable_ifaces)):
        if avaliable_ifaces[i][0]=='n':
            avaliable_ifaces[i] = avaliable_ifaces[i][1:]
    for i in range(len(avaliable_ifaces)):
        choose_ip.append(avaliable_ifaces[i] + avaliable_ip[i].replace('inet ', '') + 'x')
    return choose_ip


def scan(ip):
    arp = scapy.ARP(op=1, pdst=ip)
    ether = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    result = scapy.srp(ether/arp, timeout=1, inter=0.1, verbose=0)[0]
    clients={}
    for sent, received in result:
        clients.update({received.psrc : received.hwsrc})
    return clients



print('Choose one:',*choose_iface_ip(), sep='\n')
ip1 = str(input())
ip = ip1.replace('x','1/24')
scan = scan(ip)
print("{:<20} {:<15}".format('IP','MAC'))
for i in scan.items():
    ip, mac = i
    print("{:<20} {:<15}".format(ip, mac))
