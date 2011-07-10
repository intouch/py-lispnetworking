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
# query a mapserver for the RLOC of the given EID space
# note that this does _not_ work over NAT
# you also need root for the sockets, might fix this in the future

from lisp import *

	# define the timeout here, just in case no reply is received
timeout = 1
	# define the interface to send out on, FIXME
interface = 'eth0'
	# define the use message
use = "USAGE: ./pyLIG.py <mapserver> <eid-query>"
afi_error = "ERROR: the AFI (IPv4 / IPv6) you're trying to use is not available. check ifconfig"

	# class to resolve FQDN addresses using Google DNS. it sends out a DNS packet and returns the reply IP. right now, qtype is set to A (= IPv4), gonna fix this for AAAA (= IPv6) soon. 
def resolveFQDN(host):
    dns=DNS(rd=1,qd=DNSQR(qname=host,qtype='A'))
    response=sr1(IP(dst='8.8.8.8')/UDP()/dns)
    if response.haslayer(DNS):
        ans = response.getlayer(DNS).an
        return ans.rdata

	# check if an input is a FQDN or IP record, since they both appear as strings 
def checkFQDN(string):
    if re.match("[A-Za-z]", string):
        return resolveFQDN(string)
    else:
	return string

def sendLIG(map_server, query):
	# an alternative approach to retrieve the hosts ip is by using socket.gethostbyname(socket.gethostname()), but this unfortunatly often returns only a loopback on LINUX systems. the method below appears to work
    source_ipv4 = netifaces.ifaddresses(interface)[socket.AF_INET][0]['addr']
    source_ipv6 = netifaces.ifaddresses(interface)[socket.AF_INET6][0]['addr']
	# warn the user there is no IPv6 connectivity
    if not source_ipv6:
	print "NOTIFY: you have no IPv6 connectivity"

	# generate a random source port, this seems to be an OK range
    sport1 = random.randint(60000, 65000)
    sport2 = random.randint(60000, 65000)
    map_server_afi = int(0)
    query_afi = int(0)
    source_afi = int(0)
    source = int(0)
	# let scapy open a socket already, so that the first packet will be captured too
    server_socket = L2ListenSocket()
    
	# check if the map server specified is IPv4 or IPv6, this is important for python field lengths
	# could implement it in a method, but we use it just once anyway
    c = map_server.count(':')
    if c == 0:
		map_server_afi = 4
    elif c > 0:
		map_server_afi = 6

	# the same for the query, check for IPv4 or IPv6
    d = query.count(':')
    if d == 0:
		query_afi = 1
		eid_mask_len = 32
    elif d > 0:
		query_afi = 2
		eid_mask_len = 128

	# determine whether to use an IPv4 or IPv6 header and set some values. initiate the 'packet' too here.
    if source_ipv6 and map_server_afi == 6:
		source_afi = 2
		source = source_ipv6
		packet = IPv6(dst=map_server)
		socket_afi = socket.AF_INET6
    elif source_ipv4 and map_server_afi == 4:
		source_afi = 1
		source = source_ipv4
		packet = IP(dst=map_server)
		socket_afi = socket.AF_INET
    else:
		print afi_error

    	# build the packet with the information gathered. flags are set to smr + probe (equals 12)
    packet /= UDP(sport=sport1,dport=4342)/LISP_Encapsulated_Control_Message(ptype=8)

	# check whether to use IPv4 or IPv6 for the second IP header
    if query_afi == 1 and source_ipv4:
	packet /= IP(src=source_ipv4, dst=query, ttl=255)
    elif query_afi == 2 and source_ipv6:
	packet /= IPv6(src=source_ipv6, dst=query)

	# build the packet, uncomment the debig command below to see its structure
    packet /= UDP(sport=sport2,dport=4342)/LISP_MapRequest(request_afi=0, address=source, ptype=1, itr_rloc_records=[LISP_AFI_Address(address=source,afi=source_afi)],request_records=[LISP_MapRequestRecord(request_address=query, request_afi=query_afi, eid_mask_len=eid_mask_len)])

	# debug
    # packet.show2()

	# send packet over layer 3
    send(packet)

	# start capturing on the source port. initiate count value f
    f = 0
	# use the earlier opened socket to capture traffic on UDP port 4342
    capture = sniff(filter='udp and port 4342', timeout=timeout, opened_socket=server_socket)
    for i in range(len(capture)):
	try:	
		if capture[i].nonce == packet.nonce and capture[i].ptype == 2:
			capture[i].show2()
			f = 1
			break
	except AttributeError:
		pass

	# print message if no reply received
    if f == 0:
	print "ERROR: no reply received, are you sure you're not behind NAT and that your connectivity is OK?"

	# close the socket, else it'll stay alive for a while
    server_socket.close()

	# check command line arguments
if len(sys.argv) == 3:
	map_server = sys.argv[1]
	query = sys.argv[2]
	map_server = checkFQDN(map_server)
	query = checkFQDN(query)
	sendLIG(map_server, query)
		# if no arguments specified, drop to CLI
elif len(sys.argv) == 1:
	print use	
	if __name__ == "__main__":
        	interact(mydict=globals())
else:
		# if a weird amount of arguments is given, display usage information
	print use

