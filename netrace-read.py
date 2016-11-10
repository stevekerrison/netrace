#!/usr/bin/env python
"""
    Netrace for Python
    
    Reads a netrace compatible trace file into Python. Output format
    matches that of "trace_viewer <file> -p" from original netrace sample code.
    
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
    netrace.nt_print_trheader(ntr);
    pkt = ntr.read()
    while pkt != None:
        print ("  ID:{} CYC:{} SRC:{} DST:{} ADR:0x{:08x} TYP:{} NDEP:{} {}".format(
            pkt.id, pkt.cycle, pkt.src, pkt.dst, pkt.addr, pkt.type_str,
            pkt.num_deps, ' '.join(map(str,pkt.deps_list))))
        pkt = ntr.read()
    ntr.close()

