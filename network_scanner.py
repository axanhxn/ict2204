#!/usr/bin/env python

import scapy.all as scapy
import argparse # adding things with argparse is more simple

def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="targeted IP / IP range")
    (options) = parser.parse_args()
    return options


def scan(ip):
    req_arp = scapy.ARP(pdst=ip)
    broadcastmac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # set dst mac as broadcast mac
    broadcast_arp_req = broadcastmac/req_arp #sending arp broadcast and ARP request to automatically to go to broadcast msg
    answering_ip_list = scapy.srp(broadcast_arp_req, timeout=1, verbose=False)[0] # srp is allows sending packets with custom parts, and receive response
    #time out wait the number of seconds, then move on. If not you will get stuck of the program. Telling me to get element 0
    print("IP\t\t\tMAC address\n----------------")
    clients_list = [] # empty list create new variable
    for element in answering_ip_list: # list contains useful info of all the answered ip
        #create dictionary
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc} # getting the ip and mac address
        clients_list.append(client_dict)
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC address\n----------------")
    for client in results_list: # should get the dicts, keys and values
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
