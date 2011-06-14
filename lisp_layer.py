#!/usr/bin/env python
import scapy
from scapy import *
from scapy.all import *
import socket,struct

""" 
    GENERAL DECLARATIONS
"""

_LISP_TYPES = { 
    0 : "reserved", 
    1 : "maprequest", 
    2 : "mapreply", 
    3 : "mapregister", 
    4 : "mapnotify", 
    8 : "encapsulated_control_message" 
}

_AFI = {
    """ An AFI value of 0 used in this specification indicates an unspecified
    encoded address where the length of the address is 0 bytes
    following the 16-bit AFI value of 0."""

    "unspecified" : 0,

    """ see http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml """
    "ipv4" : 1,
    "ipv6" : 2,
    "lcaf" : 16387 
}

"""
    FIELDS

    LISPAddressField DESCRIPTION

    Dealing with addresses in LISP context, the packets often contain (afi, address)
    where the afi decides the length of the address (0, 32 or 128 bit)

    LISPAddressField will parse an IPField or an IP6Field depending on the value of 
    the AFI field. 
    
    An example would be: 
       ByteField("record_afi", 2),
       LISPAddressField("record_afi", "record_address"),

"""

class LISPAddressField(Field):
    def __init__(self, fld_name, ip_fld_name):
        Field.__init__(self, "LISP Address Field", None)
        
        self.fld_name=fld_name
        self._ip_field=IPField(ip_fld_name, "192.168.1.1")
        self._ip6_field=IP6Field(ip_fld_name, "2001:db8::1")

    def getfield(self, pkt, s):
        if getattr(pkt, self.fld_name) == _AFI["ipv4"]:
            return _ip_field.getfield(pkt,s)
        elif getattr(pkt, self.fld_name) == _AFI["ipv6"]:
            return _ip6_field.getfield(pkt,s)
    
    def addfield(self, pkt, s, val):
        if getattr(pkt, self.fld_name) == _AFI["ipv4"]:
            return self._ip_field.addfield(pkt, s, val)
        elif getattr(pkt, self.fld_name) == _AFI["ipv6"]: 
            return self._ip6_field.addfield(pkt, s, val)

"""CLASS TO DETERMINE WHICH PACKET TYPE TO INTERPRET"""

class LISPType(Packet):
    """ first part of any lisp packet """
    name = "LISP packet type"
    fields_desc = [
        BitEnumField("packettype", None, 4, _LISP_TYPES),
    ]

"""RECORD FIELDS, PART OF THE REPLY, REQUEST, NOTIFY OR REGISTER PACKET CLASSES"""

class LISPSourceRLOC(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("eid_src_afi", 2),                                                        # read out the AFI
        ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==10)     # TODO read out of the v6 AFI, not sure about AFI number yet 
         ]

class LISPSourceEID(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("eid_src_afi", 2),                                                        # read out the AFI
        ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==10)     # TODO read out of the v6 AFI, not sure about AFI number yet 
    ]

class LISPRecord(Packet):
    name = "Mapping Record"
    fields_desc = [
        ShortField("record_ttl", 0),
        ByteField("locator_count", 0),
        ByteField("eid_mask_length", 0),
        BitField("ACT", 0, 3),
        BitField("A", 0, 1),
        BitField("reserved", 0, 16),
        BitField("map_version_number", 0, 12),
        ShortField("eid_prefix_afi", 0),
        IPField("eid_prefix", "2.2.2.2"),
#        ConditionalField(IPField("v4_eids", '10.0.0.1'), lambda pkt:pkt.record_afi==1),     # read out of the v4 AFI, this field is 1 by default
#        ConditionalField(IP6Field("v6_eids", '2001::1'), lambda pkt:pkt.record_afi==2)     # TODO read out of the v6 AFI, not sure about AFI nr. 
        ByteField("priority", 0),
        ByteField("weight", 0),
        ByteField("m_priority", 0),
        ByteField("m_weight", 0),
        BitField("reserved", 0, 13),
        FlagsField("flags", 0, 3, ["L", "p", "R"]),
        ShortField("locator_afi", 0),
        IPField("locator_address", "1.1.1.1"),
    ]

class LISPMapReplyRLOC(Packet):
    name = "Map Reply RLOC record, N times determined by the record count field"
    fields_desc = [
        ByteField("priority", 1),                                               # unicast traffic priority
        ByteField("weight", 1),                                                 # unicast traffic weight
        ByteField("m_priority", 1),                                             # multicast traffic priority
        ByteField("m_weight", 1),                                               # multicast traffic weight
        BitField("unused_flags", "0"*13, 13),                                   # field reserved for unused flags
        FlagsField("flags", None, 3, ["local_locator", "probe", "route"]),      # flag fields -  "L", "p", "R"  
        ByteField("rloc_add", 4)                                                # the actual RLOC address
    ]

"""PACKET TYPES (REPLY, REQUEST, NOTIFY OR REGISTER"""

class LISPMapRequest(Packet):
    """ request part after the first 4 bits of a LISP message """
    name = "LISP request packet"
    fields_desc = [
        FlagsField("flags", 0, 6, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        BitField("reserved_fields", None, 9),
        BitField("itr_rloc_count", 0, 5),
        ByteField("recordcount", 1),
        XBitField("nonce", None, 64),
        ByteField("source_eid_afi", 1),
        ByteField("source_eid_address", 1),
        PacketListField("rloc_records",[], LISPSourceRLOC, length_from=lambda pkt:pkt.itr_rloc_count)
    ]

class LISPMapReply(Packet):                                                    
    """ request part after the first 4 bits of a LISP message """
    name = "LISP reply packet"
    fields_desc = [
        FlagsField("flags", 0, 4, ["probe", "echo_nonce_alg", "security"]),
        ShortField("reserved_fields", 0),
        ByteField("recordcount", 0),
        XLongField("nonce", 0),
        LISPRecord,
    ]

""" assemble a test LISP packet """
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
bind_layers( LISPType, LISPMapRequest, packettype=1)
bind_layers( LISPType, LISPMapReply, packettype=2)
#bind_layers( LISPRequest, LISPSourceEID )

""" start scapy shell """
#debug mode
if __name__ == "__main__":
    interact(mydict=globals(), mybanner="lisp debug")


