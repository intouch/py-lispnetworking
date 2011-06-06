#!/usr/bin/python
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

The first 4 bits define which type it is. Depending on the type a certain decoding
strategy must be chosen. 

    code todo:
        - decypher which type is used and continue parsing the packet based on type

"""

_LISP_TYPES = { 0 : "reserved",
                1 : "maprequest",
                2 : "mapreply",
                3 : "mapregister",
                4 : "mapnotify",
                8 : "encapsulated_control_message" }

class LISPHeader(Packet):
    """ first part of any lisp packet """
    name = "LISP header"
    fields_desc = [
    ByteEnumField("type", 0, _LISP_TYPES)
    ]

"""
LISP PACKET TYPE 1: Map-Request

Packet format: 

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Nonce . . .                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         . . . Nonce                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Source-EID-AFI        |   Source EID Address  ...     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              ...                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
   Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     \ |                       EID-prefix  ...                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   Map-Reply Record  ...                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                     Mapping Protocol Data                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    code todo:
        - decode A bit
        - decode M bit
        - decode P bit
        - decode S bit
        - decode p bit
        - decode s bit
        - decode itr_rloc_count bits, these indicate how many itr-rlocs will follow, counting starts at 0
        - decode record_count bits
        - handle nonce
        - handle source_eid_afi && source_eid_address (0, 32 or 128 bits depending on source_eid_afi)
        - handle itr_rloc_afi && itr_rloc_address (32 or 128 bits depending on itr_rloc_afi), repeat depending on itr_rloc_count
        - handle record
            - a total record is 8 or 20 bytes depending on the eid_prefix_afi
            - record_count indicates how many records are stored in the message
        - handle Map-Reply Record in this context

"""

class LISPMapRequest(Packet):
    """ LISP Map Requests """
    name = "Map Request"
    fields_desc = [
        FlagsField("flags", 0, 6, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        # actually the padding should be 9 bits, but we need 3 bits in the itr_rloc_count field so we don't 
        # have to write a new field definition. The itr_rloc_count field is 5 bits and contains an integer where
        # counting is done from 0. 
        BitFieldLenField("padding", 0, 6),
        # some kind of check must be build in that if the value of itr_rloc_count is larger then 32 the first 3 bits
        # must be pushed off the stack
        ByteField("itr_rloc_count", 0),
        ByteField("record_count", 0),
        StrFixedLenField("nonce", 0, 8),
        ShortField("source_eid_afi", 0),
        ConditionalField(IPField("source_eid_address", "192.168.1.1"),
            lambda pkt:pkt.source_eid_afi == socket.AF_INET),
        ConditionalField(IP6Field("source_eid_address", "2001:db8::1"),
            lambda pkt:pkt.source_eid_afi == socket.AF_INET6),
    ]

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
	fields_desc = [XShortField("message_type", 1)]

#type specification
def LispMapRequest():
	name = "send a lisp query"
	message_type = 0001

def LispMapReply(message_type):
	name = "send a lisp reply"
	self.messagetype = message_type 


#def line(self, pkt, s, val):
#	        return s+struct.pack("%is"%self.length,self.i2m(pkt, val))


#assemble lisp packet
def createLispMessage(smr, t):
	return IP()/UDP(sport=4342,dport=4342)/LispType(messagetype=1)

def test():
	return 1
#debug mode
if __name__ == "__main__":
	interact(mydict=globals(), mybanner="lisp debug")

"""
Bind LISP into scapy stack

According to http://www.iana.org/assignments/port-numbers :

lisp-data   4341/tcp   LISP Data Packets
lisp-data   4341/udp   LISP Data Packets
lisp-cons   4342/tcp   LISP-CONS Control
lisp-control    4342/udp   LISP Data-Triggered Control

We only implemented the LISP control plane

"""

bind_layers( UDP, LISPHeader, dport=4342)
bind_layers( UDP, LISPHeader, sport=4342)
# when we are further we can let scapy decide the packetformat
bind_layers( LISPHeader, LISPMapRequest, type=1)
# bind_layers( LISPHeader, LISPMapReply, type=2)
# bind_layers( LISPHeader, LISPMapRegister, type=3)
# bind_layers( LISPHeader, LISPMapNotify, type=4)
# bind_layers( LISPHeader, LISPEncapsulatedControlMessage, type=8)


