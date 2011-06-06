#!usr/bin/python
from scapy.all import *
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP
import socket,struct

"""
A packet contains a standard outer IP header

IPv4 header:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Version|  IHL  |Type of Service|          Total Length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Identification        |Flags|      Fragment Offset    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  Time to Live | Protocol = 17 |         Header Checksum       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    Source Routing Locator                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 Destination Routing Locator                   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IPv6 header: 

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Version| Traffic Class |           Flow Label                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Payload Length        | Next Header=17|   Hop Limit   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                     Source Routing Locator                    +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       +                                                               +
       |                                                               |
       +                  Destination Routing Locator                  +
       |                                                               |
       +                                                               +
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
    code todo:
        - unpack outer_ip_header
"""

"""
A packet always contains an outer UDP header

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     / |           Source Port         |         Dest Port             |
   UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     \ |           UDP Length          |        UDP Checksum           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    code todo:
        - unpack outer_udp_header
"""

"""
After the IP and UDP header the LISP message follows. 

A LISP control plane packet can be one of four types

       Reserved:                          0    b'0000'
       LISP Map-Request:                  1    b'0001'
       LISP Map-Reply:                    2    b'0010'
       LISP Map-Register:                 3    b'0011'
       LISP Map-Notify:                   4    b'0100'
       LISP Encapsulated Control Message: 8    b'1000'

"""

class LispSMR(Packet):
	name = "smr bit that distinguishes new from old requests"
	fields_desc = [ ShortField("smr", 1) ]


class LispLocatorBits(Packet):
	name = "locator bits"
	fields_desc = [ ShortField("locatorbits", 1)]


class LispNonce(Packet):
	name = "nonce"
	fields_desc = [ ShortField("nonce", int(random.randint(0,5000)))]


class LispType(Packet):
        name = "lisptype"
        #fields_desc = [ BitEnumField("t", 0, 1, {0:"res",1:"req",2:"rep",3:"req",8:"open", 9:"pushadd",10:"pushdelete",11:"unreach"}) ]
	fields_desc = [ShortField("t", 1)]

#type specification
def LispMapRequest():
	name = "send a lisp query"
	message_type = 1

def LispMapReply():
	name = "send a lisp reply"
	message_type = 2


#def line(self, pkt, s, val):
#	        return s+struct.pack("%is"%self.length,self.i2m(pkt, val))


#assemble lisp packet
def createLispMessage(smr, t):
	return TCP()/UDP(sport=4341,dport=4341)/LispSMR()/LispLocatorBits()/LispNonce()/LispType()

def test():
	return 1
#debug mode
if __name__ == "__main__":
	interact(mydict=globals(), mybanner="lisp debug")

