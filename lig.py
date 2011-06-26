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
from lisp_layer import *

interface = 'eth0'

def sendLIG(map_server, query):
	""" an alternative approach to retrieve the hosts ip is by using socket.gethostbyname(socket.gethostname()), but this unfortunatly often returns only a loopback on LINUX systems. """
	
	source_ipv4 = netifaces.ifaddresses(interface)[socket.AF_INET][0]['addr']
	source_ipv6 = netifaces.ifaddresses(interface)[socket.AF_INET6][0]['addr']
	mapserver_afi=IP(map_server).version
	source = int(0)
	source_afi = int(0)
	
	if source_ipv6 and mapserver_afi == 2:
		source_afi = 2
		source = source_ipv6
	elif source_ipv4 and mapserver_afi == 1:
		source_afi = 1
		source = source_ipv4

	return IP(dst=map_server)/UDP(sport=random.randint(5000, 10000), dport=4342)/LISP_MapRequest(request_afi=source_afi, address=source, type=1, itr_rloc_records=[LISP_AFI_Address(address=source,afi=source_afi)],request_records=[LISP_MapRequestRecord(request_address=query)])

""" start shell """
if __name__ == "__main__":
        interact(mydict=globals())
