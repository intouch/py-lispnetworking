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
from scapy import *
from scapy.all import *
import sys, pprint, random, socket, struct
from optparse import OptionParser


""" start shell """
if __name__ == "__main__":
        interact(mydict=globals())
