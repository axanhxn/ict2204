#!/usr/bin/env python

import netfilterqueue # intercepting the packets

def process_packet(packet):
    print(packet)


queue = netfilterqueue.NetfilterQueue() # creating an instance of a netfilterqueue object, placing to variable called queue
queue.bind(0, process_packet) #connect or bind the queue to the netfilterqueue
queue.run()