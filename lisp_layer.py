#!/usr/bin/env python2.6
import scapy
from scapy import *
from scapy.all import *
import socket,struct

class LISPRecordcount(ByteField):
    holds_packets=1
    def __init__(self, name, default, recordcount):
        ByteField.__init__(self, name, default)
        self.recordcount = recordcount

    def _countRC(self, pkt):
        x = getattr(pkt,self.recordcount)
        i = 0
        while isinstance(x, LISPSourceRLOC): # or isinstance(x, DNSQR):
            x = x.payload
            i += 1
        return i

    def i2m(self, pkt, x):
        if x is None:
            x = self._countRC(pkt)
        return x
  
    def i2h(self, pkt, x):
        if x is None:
            x = self._countRC(pkt)
        return x


_LISP_TYPES = { 0 : "reserved", 1 : "maprequest", 2 : "mapreply", 3 : "mapregister", 4 : "mapnotify", 8 : "encapsulated_control_message" }
    
class LISPType(Packet):
    """ first part of any lisp packet """
    name = "LISP packet type"
    fields_desc = [
        BitEnumField("packettype", None, 4, _LISP_TYPES),
    ]

class LISPRequest(Packet):
    """ request part after the first 4 bits of a LISP message """
    name = "LISP request packet"
    fields_desc = [
        FlagsField("flags", 0, 6, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        BitField("reserved_fields", None, 9),
        BitField("itr_rloc_count", 0, 5),
        ByteField("recordcount", 1),
        ByteField("nonce", 8)
    ]

class LISPReply(Packet):                                                    
    """ request part after the first 4 bits of a LISP message """
    name = "LISP reply packet"
    fields_desc = [
        FlagsField("flags", 0, 3, ["probe", "echo_nonce_alg", "security"]),
        BitField("reserved_fields", None, 17),
        LISPRecordcount("recordcount", 0, "rc"),
        ByteField("nonce", 8)
    ]

class LISPSourceEID(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("eid_src_afi", 2),                                                        # read out the AFI
        ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==10)     # TODO read out of the v6 AFI, not sure about AFI number yet 
    ]

class LISPSourceRLOC(Packet):                                                               # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("rloc_src_afi", 2),                                                       # read out the AFI
        ConditionalField(IPField("v4_eid", '192.168.1.1'), lambda pkt:pkt.rloc_src_afi==1), # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.rloc_src_afi==10)    # TODO read out of the v6 AFI, not sure about AFI number yet 
    ]

class LISPRecord(Packet):
    name = "Map Request Record"
    fields_desc = [
        ByteField("reserved_fields", 1),                                                    #padding
        ByteField("eid_prefix_length", 1),
        ByteField("record_afi", 2),
        ConditionalField(IPField("v4_eids", '10.0.0.1'), lambda pkt:pkt.record_afi==1),     # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eids", '2001::1'), lambda pkt:pkt.record_afi==10)     # TODO read out of the v6 AFI, not sure about AFI nr. 
    ]


class LISPMapReply(Packet):
    name = "Map Reply Records, n times determined by the 'record_count' from the header" 
    fields_desc = [
        ByteField("record_ttl", 4),         # ttl
        ByteField("locator_count", 1),      # amount of locator records in the packet, see LISPReplyRLOC    
        ByteField("eid_mask_length", 1)     # mask length of the EID-space
    ]

class LISPReplyRLOC(Packet):
    name = "Map Reply RLOC record, n times determined by the record count field"
    fields_desc = [
        ByteField("priority", 1),                                               # unicast traffic priority
        ByteField("weight", 1),                                                 # unicast traffic weight
        ByteField("m_priority", 1),                                             # multicast traffic priority
        ByteField("m_weight", 1),                                               # multicast traffic weight
        BitField("unused_flags", "0"*13, 13),                                   # field reserved for unused flags
        FlagsField("flags", None, 3, ["local_locator", "probe", "route"]),      # flag fields -  "L", "p", "R"  
        ByteField("rloc_add", 4)                                                # the actual RLOC address
    ]

#assemble lisp packet
def createLispMessage():
    return IP()/UDP(sport=4342,dport=4342)/LISPType()/LISPRequest()/LISPSourceRLOC()

"""
Bind LISP into scapy stack

According to http://www.iana.org/assignments/port-numbers :

lisp-data       4341/tcp   LISP Data Packets
lisp-data       4341/udp   LISP Data Packets
lisp-cons       4342/tcp   LISP-CONS Control
lisp-control    4342/udp   LISP Data-Triggered Control

"""

bind_layers( UDP, LISPType, dport=4342)
bind_layers( UDP, LISPType, sport=4342)
bind_layers( LISPType, LISPRequest, packettype=1)
bind_layers( LISPType, LISPReply, packettype=2)
bind_layers( LISPRequest, LISPSourceEID )

""" start scapy shell """
#debug mode
if __name__ == "__main__":
    interact(mydict=globals(), mybanner="lisp debug")


