#!/usr/bin/env python
"""
    Netrace for Python
    
    Reads a netrace compatible trace file into Python
    
    Usage:
        netrace-read.py [options] <trace.tra.bz2>
    
    Options:
        -h --help                   This help text.
    
    Arguments:
        <trace.tra.bz2>             A netrace compatible trace file from (Ge)M5
                                    in bz2 format.
"""

from docopt import docopt
import netrace

if __name__ == "__main__":
    ARGS = docopt(__doc__, version='1.0')
    ntr = netrace.nt_context(ARGS['<trace.tra.bz2>'])
    pkt = ntr.read()
    while pkt != None:
        print (pkt.id)
        pkt = ntr.read()
    ntr.close()

