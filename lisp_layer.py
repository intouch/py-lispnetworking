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

_LISP_MAP_REPLY_ACTIONS = {
    0 : "no_action",
    1 : "native_forward",
    2 : "send_map_request",
    3 : "drop"
}

_AFI = {
    """ An AFI value of 0 used in this specification indicates an unspecified
    encoded address where the length of the address is 0 bytes
    following the 16-bit AFI value of 0. See the following URL for the other values:
    http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml 
    """

    "unspecified" : 0,
    "ipv4" : 1,
    "ipv6" : 2,
    "lcaf" : 16387 
}

"""CLASS TO DETERMINE WHICH PACKET TYPE TO INTERPRET"""

class LISP_Type(Packet):
    """ first part of any lisp packet, in this class we also look at which flags are set
    because scapy demands certain bit alignment. A class must contain N times 8 bit, in our case 16. """
    name = "LISP packet type and flags"
    fields_desc = [
        BitEnumField("packettype", None, 4, _LISP_TYPES),
        # MapRequest
        ConditionalField(FlagsField("flags", 0, 12, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]), lambda pkt:pkt.packettype==1), 
        # MapReply
        ConditionalField(FlagsField("flags", 0, 12, ["probe", "echo_nonce_alg", "security"]), lambda pkt:pkt.packettype==2), 
        # MapRegister 
        ConditionalField(FlagsField("flags", 0, 12, ["proxy_map_reply"]), lambda pkt:pkt.packettype==3), 
        # MapNotify
        ConditionalField(BitField("reserved", 0, 12), lambda pkt:pkt.packettype==4), 
        # Encapsulated Control Message
        ConditionalField(FlagsField("flags", 0, 12, ["security"]), lambda pkt:pkt.packettype==8), 
    ]


"""
    FIELDS

    LISPAddressField DESCRIPTION

    Dealing with addresses in LISP context, the packets often contain (afi, address)
    where the afi decides the length of the address (0, 32 or 128 bit)

    LISPAddressField will parse an IPField or an IP6Field depending on the value of 
    the AFI field. 
    
    An example would be: 
       ShortField("record_afi", 0),
       LISPAddressField("record_afi", "record_address"),

"""

class LISP_AddressField(Field):
    def __init__(self, fld_name, ip_fld_name):
        Field.__init__(self, ip_fld_name, None)
        
        self.fld_name=fld_name
        self._ip_field=IPField(ip_fld_name, "192.168.1.1")
        self._ip6_field=IP6Field(ip_fld_name, "2001:db8::1")

    def getfield(self, pkt, s):
        if getattr(pkt, self.fld_name) == _AFI["ipv4"]:
            return self._ip_field.getfield(pkt,s)
        elif getattr(pkt, self.fld_name) == _AFI["ipv6"]:
            return self._ip6_field.getfield(pkt,s)
    
    def addfield(self, pkt, s, val):
        if getattr(pkt, self.fld_name) == _AFI["ipv4"]:
            return self._ip_field.addfield(pkt, s, val)
        elif getattr(pkt, self.fld_name) == _AFI["ipv6"]: 
            return self._ip6_field.addfield(pkt, s, val)

"""RECORD FIELDS, PART OF THE REPLY, REQUEST, NOTIFY OR REGISTER PACKET CLASSES"""

class LISP_AFI_Address(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "ITR RLOC Address"
    fields_desc = [
        ShortField("afi", 0),                                                        # read out the AFI
        LISP_AddressField("afi", "address"),
        #ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        #ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==2)     # TODO read out of the v6 AFI, not sure about AFI number yet 
    ]

class LISP_MapRecord(Packet):
    name = "LISP Map-Reply Record"
    fields_desc = [
        BitField("record_ttl", 0, 32),
        ByteField("locator_count", 0),
        ByteField("eid_mask_length", 0),
        BitEnumField("action", None, 3, _LISP_MAP_REPLY_ACTIONS),
        BitField("authoritative", 0, 1),
        BitField("reserved", 0, 16),
        BitField("map_version_number", 0, 12),
# hardcoded stuff - we don't know for sure that it will be an IPv4 IPField
        ShortField("eid_prefix_afi", 0),
        IPField("eid_prefix", "2.2.2.2"),
#        ConditionalField(IPField("v4_eids", '10.0.0.1'), lambda pkt:pkt.record_afi==1),     # read out of the v4 AFI, this field is 1 by default
#        ConditionalField(IP6Field("v6_eids", '2001::1'), lambda pkt:pkt.record_afi==2)     # TODO read out of the v6 AFI, not sure about AFI nr. 
        ByteField("priority", 0),
        ByteField("weight", 0),
        ByteField("multicast_priority", 0),
        ByteField("multicast_weight", 0),
        BitField("reserved", 0, 13),
        FlagsField("flags", 0, 3, ["L", "p", "R"]),
        ShortField("locator_afi", 0),
        IPField("locator_address", "1.1.1.1"),
    ]

class LISP_MapRequestRecord(Packet):
    name= "LISP Map-Request Record"
    fields_desc = [
        ByteField("reserved", 0),
        ByteField("eid_mask_len", 0),
        ShortField("eid_prefix_afi", 0),
        IPField("eid_prefix", "1.1.1.1")
    ]

class LISP_MapReplyRLOC(Packet):
    name = "LISP Map-Reply RLOC record, N times determined by the record count field"
    fields_desc = [
        ByteField("priority", 1),                                               # unicast traffic priority
        ByteField("weight", 1),                                                 # unicast traffic weight
        ByteField("multicast_priority", 1),                                     # multicast traffic priority
        ByteField("multicast_weight", 1),                                       # multicast traffic weight
        BitField("unused_flags", "0"*13, 13),                                   # field reserved for unused flags
        FlagsField("flags", None, 3, ["local_locator", "probe", "route"]),      # flag fields -  "L", "p", "R"  
        ByteField("rloc_add", 4)                                                # the actual RLOC address
    ]

"""PACKET TYPES (REPLY, REQUEST, NOTIFY OR REGISTER)"""

class LISP_MapRequest(Packet):
    """ map request part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Request packet"
    fields_desc = [
        FieldLenField("itr_rloc_count", 0, fmt='B', count_of="rloc_records"),
        FieldLenField("recordcount", 0, fmt='B', count_of="eid_records"),
        XLongField("nonce", 0),
        ShortField("source_eid_afi", 0),
        LISP_AddressField("source_eid_afi", "source_eid_address"),
        PacketListField("rloc_records", None, LISP_AFI_Address, count_from=lambda pkt: pkt.itr_rloc_count+1),
        PacketListField("eid_records", None, LISP_AFI_Address, count_from=lambda pkt: pkt.recordcount+1)
    ]

class LISP_MapReply(Packet):                                                    
    """ map reply part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Reply packet"
    fields_desc = [
        ByteField("reserved_fields", 0),
        ByteField("recordcount", 0),
        XLongField("nonce", 0),
        LISP_MapRecord
    ]


""" assemble a test LISP packet """
def createLispMessage():
    return IP()/UDP(sport=4342,dport=4342)/LISP_Type()/LISP_MapRequest()/LISP_SourceRLOC()


"""
Bind LISP into scapy stack

According to http://www.iana.org/assignments/port-numbers :

lisp-data       4341/tcp   LISP Data Packets
lisp-data       4341/udp   LISP Data Packets
lisp-cons       4342/tcp   LISP-CONS Control
lisp-control    4342/udp   LISP Data-Triggered Control

"""

bind_layers( UDP, LISP_Type, dport=4342)
bind_layers( UDP, LISP_Type, sport=4342)
bind_layers( LISP_Type, LISP_MapRequest, packettype=1)
bind_layers( LISP_Type, LISP_MapReply, packettype=2)
#bind_layers( LISPRequest, LISPSourceEID )

""" start scapy shell """
#debug mode
if __name__ == "__main__":
    interact(mydict=globals(), mybanner="lisp debug")


