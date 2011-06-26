#!/usr/bin/env python2.6
"""
    This file is part of a toolset to manipulate LISP control-plane
    packets "py-lispnetworking".

    Copyright (C) 2011 Marek Kuczynski <marek@intouch.eu>
    Copyright (C) 2011 Job Snijders <job@intouch.eu>

    This file is subject to the terms and conditions of the GNU General
    Public License. See the file COPYING in the main directory of this
    archive for more details.
"""

import scapy,socket,struct,random,fcntl,netifaces,IPy
from scapy import *
from scapy.all import *

"""  GENERAL DECLARATIONS """

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
    """ An AFI value of 0 used in this specification indicates an unspecified encoded address where the length of the address is 0 bytes following the 16-bit AFI value of 0. See the following URL for the other values:
    http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xml """

    "zero" : 0,
    "ipv4" : 1,
    "ipv6" : 2,
    "lcaf" : 16387 
}

""" nonce_max determines the maximum value of a nonce field. The default is set to 18446744073709551615, since this is the maximum possible value (>>> int('f'*16, 16)). TODO - see about the entropy for this source"""

nonce_max = 16777215000

"""CLASS TO DETERMINE WHICH PACKET TYPE TO INTERPRET
scapy is designed to read out bytes before it can call another class. we are using the ugly conditional construction you see below to circumvent this, since all classes must have the length of one or more bytes. improving and making this prettier is still on the TODO list """

class LISP_Type(Packet):
    def guess_payload_class(self, payload):
       	# read the payload (non interpreted part of the packet string) into a variable
    	a = payload[:1]
		# put the hex from the packet remainder into an attribute
        b = struct.unpack("B", a)
		# shift the value from the attribute for 4 bits, so that we have only the 4 bit type value that we care about in the form of a byte. this means that flags are not taken into account in this value, which makes enumeration much cleaner and easier.
        c = b[0] >> 4
		
		# compare the integer from the value to the packettype and continue to the correct class
        if c == 1:
            return LISP_MapRequest      
        elif c == 2:
            return LISP_MapReply
        elif c == 3:
            return LISP_MapRegister
        elif c == 8:
            return LISP_Encapsulated_Control_Message
        else:
            return payload

    
""" the class below reads the first byte of an unidentified IPv4 or IPv6 header. it then checks the first byte of the payload to see if its IPv4 or IPv6 header. the IPv4 header contains a byte to describe the IP version, which is always hex45. IPv6 has a 4 bit header, which is harder to read in scapy. maybe this can be done in a prettier way - TODO """

class LCAF_Type(Packet):
    def guess_payload_class(self, payload):
	a = payload[:1]
        b = struct.unpack("B", a)
        c = b[0] >> 4

        if c == 4:
            return IP
        elif c == 6:
            return IPv6
        elif c == 16387:
	        print "LCAF, WIP"
        else:
	        return payload

""" 
LISPAddressField, Dealing with addresses in LISP context, the packets often contain (afi, address) where the afi decides the length of the address (0, 32 or 128 bit). LISPAddressField will parse an IPField or an IP6Field depending on the value of the AFI field. 
    
"""

class LISP_AddressField(Field):
    def __init__(self, fld_name, ip_fld_name):
        Field.__init__(self, ip_fld_name, '1')

        self.fld_name=fld_name
        self._ip_field=IPField(ip_fld_name, '127.0.0.1')
        self._ip6_field=IP6Field(ip_fld_name, '::1')

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

""" LISP Address Field, used multiple times whenever an AFI determines the length of the IP field. for example, IPv4 requires 32 bits of storage while IPv6 needs 128 bits. This field can easily be extended once new LISP LCAF formats are needed, see the LISP_AddressField class for this. """
class LISP_AFI_Address(Packet):                     # used for 4 byte fields that contain a AFI and a v4 or v6 address
    name = "ITR RLOC Address"
    fields_desc = [
        ShortField("afi", int(1)),
        LISP_AddressField("afi", "address")
    ]

    def extract_padding(self, s):
        return "", s

""" Map Reply LOCATOR, page 28, paragraph 6.1.4, the LOCATOR appears N times dependant on the locator count in the record field """
class LISP_Locator_Record(Packet):
    name = "LISP Locator Records"
    fields_desc = [
        ByteField("priority", 0),
        ByteField("weight", 0),
        ByteField("multicast_priority", 0),
        ByteField("multicast_weight", 0),
        BitField("reserved", 0, 13), 
        FlagsField("locator_flags", 0, 3, ["local_locator", "probe", "route"]), 
        ShortField("locator_afi", int(1)),
        LISP_AddressField("locator_afi", "address")
    ]

    # delimits the packet, so that the remaining records are not contained as 'raw' payloads 
    def extract_padding(self, s):
        return "", s

""" Map Reply RECORD, page 28, paragraph 6.1.4, the RECORD appears N times dependant on Record Count """
class LISP_MapRecord(Packet):
    name = "LISP Map-Reply Record"
    fields_desc = [
        BitField("record_ttl", 0, 32),
        FieldLenField("locator_count",  None, "locators", "B", count_of="locators", adjust=lambda pkt,x:x/12),
        ByteField("eid_prefix_length", 0),
        BitEnumField("action", 0, 3, _LISP_MAP_REPLY_ACTIONS),
        BitField("authoritative", 0, 1),
        BitField("reserved", 0, 16),
        BitField("map_version_number", 0, 12),
        ShortField("record_afi", int(1)),
        LISP_AddressField("record_afi", "record_address"),
        PacketListField("locators", None, LISP_Locator_Record, count_from=lambda pkt: pkt.locator_count + 1)
    ]

    # delimits the packet, so that the remaining records are not contained as 'raw' payloads
    def extract_padding(self, s):
        return "", s

""" Map Request RECORD, page 25, paragraph 6.1.2, the 'REC', appears N times depending on record count """
class LISP_MapRequestRecord(Packet):
    name= "LISP Map-Request Record"
    fields_desc = [
        ByteField("reserved", 0),
	        # eid mask length
        ByteField("eid_mask_len", 24),
        	# eid prefix afi
        ShortField("request_afi", int(1)),
	        # eid prefix information + afi
        LISP_AddressField("request_afi", "request_address")
    ]
   
    def extract_padding(self, s):
        return "", s

"""PACKET TYPES (REPLY, REQUEST, NOTIFY OR REGISTER)"""

class LISP_MapRequest(Packet):
    """ map request part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Request packet"
    fields_desc = [
        BitField("type", 0, 4),
        FlagsField("request_flags", None, 6, ["authoritative", "map_reply_included", "probe", "smr", "pitr", "smr_invoked"]),
        BitField("p1", 0, 6),
            # Right now we steal 3 extra bits from the reserved fields that are prior to the itr_rloc_records
        FieldLenField("itr_rloc_count", None, "itr_rloc_records", "B", count_of="itr_rloc_records", adjust=lambda pkt,x:x / 6 - 1),                          
        FieldLenField("request_count", None, "request_records", "B", count_of="request_records", adjust=lambda pkt,x:x / 8),  
        XLongField("nonce", random.randint(0, nonce_max)),
            # below, the source address of the request is listed, this occurs once per packet
        ShortField("request_afi", int(1)),
            # the LISP IP address field is conditional, because it is absent if the AFI is set to 0
        ConditionalField(LISP_AddressField("request_afi", "address"), lambda pkt:pkt.request_afi != 0),
        PacketListField("itr_rloc_records", None, LISP_AFI_Address, count_from=lambda pkt: pkt.itr_rloc_count + 1),
        PacketListField("request_records", None, LISP_MapRequestRecord, count_from=lambda pkt: pkt.request_count) 
    ]

class LISP_MapReply(Packet):                                                    
    """ map reply part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Reply packet"
    fields_desc = [
        BitField("type", 0, 4),
        FlagsField("reply_flags", None, 3, ["probe", "echo_nonce_alg", "security" ]),
        BitField("p2", 0, 9),        
        BitField("reserved", 0, 8),
        FieldLenField("map_count", 0, "map_records", "B", count_of="map_records", adjust=lambda pkt,x:x/16 - 1),  
	XLongField("nonce", random.randint(0, nonce_max)),
        PacketListField("map_records", 0, LISP_MapRecord, count_from=lambda pkt:pkt.map_count + 1)
    ]

class LISP_MapRegister(Packet):
    """ map reply part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Register packet"
    fields_desc = [ 
        BitField("type", 0, 4),
        FlagsField("register_flags", None, 1, ["proxy_map_reply"]),
        BitField("p3", 0, 18), 
        FlagsField("register_flags", None, 1, ["want-map-notify"]),
        FieldLenField("register_count", None, "register_records", "B", count_of="register_records", adjust=lambda pkt,x:x / 16 - 1),
        XLongField("nonce", random.randint(0, nonce_max)),
	ShortField("key_id", 0),
        ShortField("authentication_length", 0),
            # authentication length expresses itself in bytes, so no modifications needed here
        StrLenField("authentication_data", None, length_from = lambda pkt: pkt.authentication_length),
        PacketListField("register_records", None, LISP_MapRecord, count_from=lambda pkt:pkt.register_count + 1)
    ]

class LISP_MapNotify(Packet):
    """ map notify part used after the first 16 bits have been read by the LISP_Type class"""
    name = "LISP Map-Notify packet"
    fields_desc = [
        BitField("type", 0, 4),
        BitField("reserved", 0, 12),
        ByteField("reserved_fields", 0),
        FieldLenField("notify_count", None, "notify_records", "B", count_of="notify_records"),
	XLongField("nonce", random.randint(0, nonce_max)),
        ShortField("key_id", 0),
        ShortField("authentication_length", 0),
            # authentication length expresses itself in bytes, so no modifications needed here
        StrLenField("authentication_data", None, length_from = lambda pkt: pkt.authentication_length),
        PacketListField("notify_records", None, LISP_MapRecord, count_from=lambda pkt: pkt.notify_count)
    ]

class test(Packet):
	fields_desc = [
		SourceIPField("aaa",0)
	]


class LISP_Encapsulated_Control_Message(Packet):
    name = "LISP Encapsulated Control Message packet"
    fields_desc = [
        BitField("type", 0, 4),	
    	FlagsField("ecm_flags", None, 1, ["security"]),
    	BitField("p8", 0, 27) 
    ]

    """ Bind LISP into scapy stack
    
    According to http://www.iana.org/assignments/port-numbers :
    lisp-data       4341/tcp   LISP Data Packets
    lisp-data       4341/udp   LISP Data Packets
    lisp-cons       4342/tcp   LISP-CONS Control
    lisp-control    4342/udp   LISP Data-Triggered Control """

    # tie LISP into the IP/UDP stack
bind_layers( UDP, LISP_Type, dport=4342 )
bind_layers( UDP, LISP_Type, sport=4342 )
bind_layers( LISP_Encapsulated_Control_Message, LCAF_Type, )

""" start scapy shell """
if __name__ == "__main__":
    interact(mydict=globals(), mybanner="lisp debug")
