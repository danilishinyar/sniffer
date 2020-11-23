import scapy.all as scapy
import time

def get_mac(ip):
    pkt_arp = scapy.ARP(pdst=ip)
    pkt_ether = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt_ether/pkt_arp
    r = scapy.srp(pkt,timeout=1, verbose=False)[0]
    return r[0][1].hwsrc


def detect(pkt):
    try:
        if pkt['ARP'].op == 2:
            real_mac = get_mac(pkt['ARP'].psrc)
            resp_mac = pkt['ARP'].hwsrc
            if real_mac != resp_mac:
                print(f'ATTACK, REAL-MAC: {real_mac}, FAKE-MAC: {resp_mac}\n' )
                time.sleep(5)
    except IndexError:
            print('YOU ARE NOT UNDER ATTACK\n')
            time.sleep(50)
