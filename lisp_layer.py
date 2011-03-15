#!/usr/bin/env python
from scapy.all import *
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP
import socket,struct

""" Will parse an IPField or an IP6Field depending on the value of the AFI field. """
class LISPAddressField(Field):
    _ip_field=IPField("source_eid_address", "192.168.1.1")
    _ip6_field=IP6Field("source_eid_address", "2001:db8::1")
    
    def __init__(self):
        Field.__init__(self, "LISP Address Field", None)
    
    def getfield(self, pkt, s):
        if pkt.source_eid_afi == socket.AF_INET:
            return _ip_field.getfield(pkt,s)
        elif pkt.source_eid_afi == socket.AF_INET6:
            return _ip6_field("source_eid_address", "2001:db8::1").getfield(pkt,s)
    
    def addfield(self, pkt, s, val):
        if pkt.source_eid_afi == socket.AF_INET:
            return self._ip_field.addfield(pkt, s, val)
        elif pkt.source_eid_afi == socket.AF_INET6:
            return self._ip6_field.addfield(pkt, s, val)
                
#class ConditionalField:
#    fld = None
#    def __init__(self, fld, cond):
#        self.fld = fld
#        self.cond = cond
#    def _evalcond(self,pkt):
#        return self.cond(pkt)

#    def getfield(self, pkt, s):
#        if self._evalcond(pkt):
#            return self.fld.getfield(pkt,s)
#        else:
#            return s,None
#
#    def addfield(self, pkt, s, val):
#        if self._evalcond(pkt):
#            return self.fld.addfield(pkt,s,val)
#        else:
#            return s


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
    BitEnumField("type", 0, 4, _LISP_TYPES)
	]

"""
LISP PACKET TYPE 1: Map-Request

Packet format: 

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Nonce . . .                           |      class LISPRequest
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         . . . Nonce                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |         Source-EID-AFI        |   Source EID Address  ...     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      
       |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |      
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  --- N x class LISPRequestRLOCRecord -
       |                              ...                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      N = IRC field
       |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
     / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |      N x class LISPRequestEIDRecord
   Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      
     \ |                       EID-prefix  ...                         |      N = Record Count field
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |                   Map-Reply Record  ...                       |      1 x EID to RLOC mapping
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |                     Mapping Protocol Data                     |      Optional field (still not used?)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------

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

class LISPRequest(Packet):
    name = "Map Request"
    fields_desc = [
        FlagsField("flags", None, 6, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        BitField("padding", "0"*9, 9),
        BitField("itr_rloc_count", "0"*5, 5),
        ByteField("record_count", 0),
        StrFixedLenField("nonce", int(random.randint(0,100000000)), 8),
    # TODO: we need to fix socket.AF_INET6 here because in python/socket module IP6 is 30 but on the wire it will be 2
        ShortField("source_eid_afi", socket.AF_INET6),
#        ConditionalField(IPField("source_eid_address", "192.168.1.1"),
#            lambda pkt:pkt.source_eid_afi == socket.AF_INET),
#        ConditionalField(IP6Field("source_eid_address", "2001:db8::1"),
#            lambda pkt:pkt.source_eid_afi == socket.AF_INET6),
        LISPAddressField()
	]

#class LISPRequestEIDRecord(Packet):
	#source eid afi
	#source eid
	#itr-rloc-afi
	#itr-rloc-add

    

class LISPRequestRLOCRecord(Packet):
    name = "Map Request Record"
    fields_desc = [
	ByteField("reserved", 1),
	ByteField("eid_mask_length", 1),
    # TODO: we need to fix socket.AF_INET6 here because in python/socket module IP6 is 30 but on the wire it will be 2
        ShortField("source_eid_afi", socket.AF_INET6),
        ConditionalField(IPField("source_eid_address", "192.168.1.1"),
            lambda pkt:pkt.source_eid_afi == socket.AF_INET),
        ConditionalField(IP6Field("source_eid_address", "2001:db8::1"),
            lambda pkt:pkt.source_eid_afi == socket.AF_INET6),
	ByteField("eid_prefix", 4)
	]
		
"""
        
LISP PACKET TYPE 2: Map-Reply

	0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |Type=2 |P|E|S|          Reserved               | Record Count  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Nonce . . .                           |      class LISPMapReply
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         . . . Nonce                           |
   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
   |   |                          Record  TTL                          |
   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |      N x class LISPReplyRecord
   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   c   | Rsvd  |  Map-Version Number   |       EID-prefix-AFI          |      N = Record Count field
   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   r   |                          EID-prefix                           |
   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      N x class LISPReplyRLOC
   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      N = Locator Count field
   |  \|                             Locator                           |
   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
       |                     Mapping Protocol Data                     |      1 x Authentication (optional!)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ }-------------------------------------
"""


class LISPMapReply(Packet):
    name = "Map Reply Header"
    fields_desc = [
        FlagsField("flags", None, 3, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        BitField("padding", "0"*17, 17),     # reserved bytes, filled with 0's
        ByteField("record_count", "0"*8),    # amount of records in a map reply
        StrFixedLenField("nonce", int(random.randint(0,100000000)), 8)]            # nonce containing random integer

class LISPMapReplyRecord(Packet):
    name = "Map Reply Records, n times determined by the 'record_count' from the header" 
    fields_desc = [
	ByteField("record_ttl", 4),	    # ttl
	ByteField("locator_count", 1),      # amount of locator records in the packet, see LISPReplyRLOC    
	ByteField("eid_mask_length", 1)     # mask length of the EID-space
	]
class LISPReplyRLOC(Packet):
    name = "Map Reply RLOC record, n times determined by the record count field"
    fields_desc = [
	ByteField("priority", 1),           # unicast traffic priority
	ByteField("weight", 1),             # unicast traffic weight
	ByteField("m_priority", 1),         # multicast traffic priority
	ByteField("m_weight", 1),           # multicast traffic weight
	BitField("unused_flags", "0"*13, 13), 					   # field reserved for unused flags
	FlagsField("flags", None, 3, ["local_locator", "probe", "route"]),         # flag fields -  "L", "p", "R"  
	ByteField("rloc_add", 4)            # the actual RLOC address
	]

#assemble lisp packet
def createLispMessage():
	return IP()/UDP(sport=4342,dport=4342)/LISPHeader()
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
bind_layers( LISPHeader, LISPMapReply, type=2)
bind_layers( LISPHeader, LISPMapRegister, type=3)
bind_layers( LISPHeader, LISPMapNotify, type=4)
# bind_layers( LISPHeader, LISPEncapsulatedControlMessage, type=8)
