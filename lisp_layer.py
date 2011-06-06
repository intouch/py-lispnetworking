#!usr/bin/python
from scapy.all import *
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import UDP
import socket,struct


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
	t = 1

def LispMapReply():
	name = "send a lisp reply"
	t = 2


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

