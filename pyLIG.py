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

from lib_pylispnetworking import *

# define the timeout here, just in case no reply is received
timeout = 3
# define the interface to send out on, FIXME
interface = 'eth0'

def sendLIG(map_server, query, eid_mask_len):
    # an alternative approach to retrieve the hosts ip is by using socket.gethostbyname(socket.gethostname()), but this unfortunatly often returns only a loopback on LINUX systems. the method below appears to work
    source_ipv4 = netifaces.ifaddresses(interface)[socket.AF_INET][0]['addr']
    source_ipv6 = netifaces.ifaddresses(interface)[socket.AF_INET6][0]['addr']
    # generate a random source port
    sport = random.randint(60000, 65000)
    map_server_afi = int(0)
    query_afi = int(0)
    source_afi = int(0)
    source = int(0)
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
    elif c > 0:
		query_afi = 2

	# determine whether to use an IPv4 or IPv6 header
    if source_ipv6 and map_server_afi == 6:
		source_afi = 2
		source = source_ipv6
		packet = IPv6(dst=map_server)
		packet_encap = IPv6(dst=map_server)
		socket_afi = socket.AF_INET6
    elif source_ipv4 and map_server_afi == 4:
		source_afi = 1
		source = source_ipv4
		packet = IP(dst=map_server)
		packet_encap = IP(dst=map_server)
		socket_afi = socket.AF_INET

    	# build the packet with the information gathered. flags are set to smr + probe (equals 12)
    packet_encap /= UDP(sport=46380,dport=4342)/LISP_Encapsulated_Control_Message(ptype=8)/IP(src=source, dst=source, ttl=255)/UDP(sport=sport,dport=4342)/LISP_MapRequest(request_afi=0, address=source, ptype=1, itr_rloc_records=[LISP_AFI_Address(address=source,afi=source_afi)],request_records=[LISP_MapRequestRecord(request_address=query, request_afi=query_afi, eid_mask_len=eid_mask_len)])
    packet /= UDP(sport=46380,dport=4342)/UDP(sport=sport,dport=4342)/LISP_MapRequest(request_afi=0, address=source, ptype=1, itr_rloc_records=[LISP_AFI_Address(address=source,afi=source_afi)],request_records=[LISP_MapRequestRecord(request_address=query, request_afi=query_afi, eid_mask_len=eid_mask_len)])

	# print 'sending the following...'
	# packet.show2()
	# print '...'
	
	# send packet over layer 3
    send(packet)

	# start capturing on the source port
    capture = sniff(filter='port 4342', timeout=timeout, opened_socket=server_socket)
    found = 0
    for i in range(len(capture)):
	try:	
		#if capture[i].nonce == packet.nonce and capture[i].ptype == 2:
		if capture[i].ptype == 2:
			capture[i].show2()
			server_socket.close()
			found = 1
			#break
	except AttributeError:
		pass

    if found != 1:
	print 'no replies received, are you sure you\'re not behind NAT?'
	server_socket.close()

# start pyLIG shell
if __name__ == "__main__":
        interact(mydict=globals())
