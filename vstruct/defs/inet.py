'''
Datalink / Network / Transport layer headers
'''
import socket
import struct

import vstruct
from vstruct.primitives import *

ETH_P_IP    = 0x0800

IPPROTO_ICMP    = 1
IPPROTO_TCP     = 6
IPPROTO_UDP     = 17
IPPROTO_IPV6    = 41

TCP_F_FIN  = 0x01
TCP_F_SYN  = 0x02
TCP_F_RST  = 0x04
TCP_F_PUSH = 0x08
TCP_F_ACK  = 0x10
TCP_F_URG  = 0x20
TCP_F_ECE  = 0x40
TCP_F_CWR  = 0x80

# Useful combinations...
TCP_F_SYNACK = (TCP_F_SYN | TCP_F_ACK)

def reprIPv4Addr(addr):
    bytes = struct.pack('>I', addr)
    return socket.inet_ntoa(bytes)

def decIPv4Addr(addrstr):
    bytes = socket.inet_aton(addrstr)
    return struct.unpack('>I', bytes)[0]

class IPv4Address(v_uint32):

    def __init__(self, value=0):
        v_uint32.__init__(self, value=value, bigend=True)

    def __repr__(self):
        bytes = struct.pack('>I', self._vs_value)
        return socket.inet_ntop(socket.AF_INET, bytes)

class ETHERII(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.destmac    = v_bytes(size=6)
        self.srcmac     = v_bytes(size=6)
        self.etype      = v_uint16(bigend=True)

class IPv4(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.veriphl    = v_uint8()
        self.tos        = v_uint8()
        self.totlen     = v_uint16(bigend=True)
        self.ipid       = v_uint16(bigend=True)
        self.flagfrag   = v_uint16(bigend=True)
        self.ttl        = v_uint8()
        self.proto      = v_uint8()
        self.cksum      = v_uint16(bigend=True)
        self.srcaddr    = IPv4Address()
        self.dstaddr    = IPv4Address()

    # Make our len over-ride
    def __len__(self):
        return (self.veriphl & 0x0f) * 4


class TCP(vstruct.VStruct):

    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.srcport    = v_uint16(bigend=True)
        self.dstport    = v_uint16(bigend=True)
        self.sequence   = v_uint32(bigend=True)
        self.ackseq     = v_uint32(bigend=True)
        self.doff       = v_uint8()
        self.flags      = v_uint8()
        self.window     = v_uint16(bigend=True)
        self.checksum   = v_uint16(bigend=True)
        self.urgent     = v_uint16(bigend=True)

    def __len__(self):
        return self.doff >> 2

class UDP(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.srcport    = v_uint16(bigend=True)
        self.dstport    = v_uint16(bigend=True)
        self.udplen     = v_uint16(bigend=True)
        self.checksum   = v_uint16(bigend=True)

