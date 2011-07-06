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
		socket_afi = socket.AF_INET6
    elif source_ipv4 and map_server_afi == 4:
		source_afi = 1
		source = source_ipv4
		packet = IP(dst=map_server)
		socket_afi = socket.AF_INET

	# open the socket already, so that its ready once the packet is sent
    server_socket = socket.socket(socket_afi, socket.SOCK_RAW, socket.IPPROTO_RAW)
    server_socket.bind((source, sport))
    server_socket.setsockopt(socket.SOL_IP, socket.SO_RCVBUF, 0)
	
    # build the packet with the information gathered. flags are set to smr + probe (equals 12)
    packet /= UDP(sport=sport,dport=4342)/LISP_MapRequest(request_flags=12, request_afi=source_afi, address=source, ptype=1, itr_rloc_records=[LISP_AFI_Address(address=source,afi=source_afi)],request_records=[LISP_MapRequestRecord(request_address=query, request_afi=query_afi, eid_mask_len=eid_mask_len)])

    # send packet over layer 3
    send(packet)

# start capturing on the source port
    capture = sniff(filter='udp and port 4342', timeout=timeout) #,opened_socket=server_socket)
    for i in range(len(capture)):
		capture[i].show2()
		server_socket.close()
		break

""" start shell """
if __name__ == "__main__":
        interact(mydict=globals())
