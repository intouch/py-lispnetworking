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

class LISPType(Packet):
    """ first part of any lisp packet """
    name = "LISP packet type"
    fields_desc = [
        BitEnumField("packettype", None, 4, _LISP_TYPES),
    ]

class LISPSourceEID(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("eid_src_afi", 2),                                                        # read out the AFI
        ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        ConditionalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==10)     # TODO read out of the v6 AFI, not sure about AFI number yet 
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
        ByteField("recordcount", 0),
        ByteField("nonce", 8),
        PacketListField("parameters",[], LISPSourceEID, length_from=lambda pkt:pkt.recordcount)
    ]

class LISPSourceEID(Packet):                                                                # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "reply record containing the source eid address"
    fields_desc = [
        ByteField("eid_src_afi", 2),                                                        # read out the AFI
        ConditionalField(IPField("v4_eid", '10.0.0.1'), lambda pkt:pkt.eid_src_afi==1),     # read out of the v4 AFI, this field is 1 by default
        Conditi"ckettype= mapreply
###[ LISP reply packet ]###
                         flags= security
                                          reserved_fields= 0L
                                                           recordcount= 2
                                                                            nonce= 174
                                                                                             \parameters\
                                                                                                               |###[ reply record containing the source eid address ]###
                                                                                                                                 |  eid_src_afi= 146
###[ Raw ]###
                                                                                                                                                     load= '\xb5WO\x84\x9c\xd0\x00\x00\x05\xa0\x01 \x10\x00\x00\x00\x00\x01\xac\x10\x1f\x01\x00d\xff\x00\x00\x07\x00\x01\xd4\x1a\xc5\x03'
                                                                                                                                                     >>> quit()
                                                                                                                                                     marek@mini:~/py-lispnetworking$ ./lisp_layer.py 
                                                                                                                                                     Welcome to Scapy (2.1.0)
                                                                                                                                                     lisp debug
                                                                                                                                                     >>> a=rdpcap("./1.pcap")
                                                                                                                                                     >>> a[10]
                                                                                                                                                     <Ether  dst=00:1a:e3:dc:2c:80 src=00:1f:6c:c3:2a:92 type=0x8100 |<Dot1Q  prio=0L id=0L vlan=105L type=0x800 |<IP  version=4L ihl=5L tos=0xc0 len=60 id=12 flags= frag=0L ttl=32 proto=udp chksum=0xc7f0 src=92.254.28.189 dst=85.184.2.130 options=[] |<UDP  sport=4342 dport=4342 len=40 conalField(IP6Field("v6_eid", '2001::1'), lambda pkt:pkt.eid_src_afi==10)     # TODO read out of the v6 AFI, not sure about AFI number yet 
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
#bind_layers( LISPRequest, LISPSourceEID )

""" start scapy shell """
#debug mode
if __name__ == "__main__":
    interact(mydict=globals(), mybanner="lisp debug")


