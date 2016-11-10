#!/usr/bin/env python
"""
    Netrace for Python
    
    Reads a netrace compatible trace file into Python. Output format
    matches that of "trace_viewer <file> -p" from original netrace sample code.
    
    This version is implemented in native python rather with Swig, to see
    if I'm any better at writing stuff in pure Python.
    
    Usage:
        netrace-read.py [options] <trace>
    
    Options:
        -h --help                   This help text.
    
    Arguments:
        <trace>                     A netrace compatible trace file from (Ge)M5
                                    in bz2, gzip or uncompressed format.
"""

from docopt import docopt
import magic
import gzip
import bz2
import struct
from collections import namedtuple

class netrace_packet:
    def __init__(self, data):
        self.data = data
    def __str__(self):
        return str(self.data)

class netrace:

    MAGIC = 0x484A5455
    NOTES_LIMIT = 8192
    PACKET_FORMAT = "<QIIBBBBB"
    PACKET_LENGTH = struct.calcsize(PACKET_FORMAT)

    def __init__(self, filename):
        self.fh = self.open_trace(filename)
        self.read_header(self.fh)
        self.read_regions(self.fh)
        self.hdr['size'] = self.fh.tell()
        self.header_str()
    
    def read_packet(self):
        Packet = namedtuple("Packet",
            "cycle id addr type src dst node_types num_deps")
        data = self.fh.read(self.PACKET_LENGTH)
        if len(data) != self.PACKET_LENGTH:
            return None
        pkt = netrace_packet(Packet._asdict(
            Packet._make(struct.unpack(self.PACKET_FORMAT, data))
        ))
        return pkt
        
    def header_str(self):
        self.header = """NT_TRACEFILE---------------------
  Benchmark: {}
  Magic Correct? TRUE
  Tracefile Version: v{}
  Number of Program Regions: {}
  Number of Simulated Nodes: {}
  Simulated Cycles: {}
  Simulated Packets: {}
  Average injection rate: {:.6f}
  Notes: {}""".format(
            self.hdr['benchmark_name'],
            self.hdr['version'],
            self.hdr['num_regions'],
            self.hdr['num_nodes'],
            self.hdr['num_cycles'],
            self.hdr['num_packets'],
            float(self.hdr['num_packets']) / self.hdr['num_cycles'],
            self.hdr['notes']
        )
        for n, r in enumerate(self.hdr['regions']):
            self.header += """
        Region {}:
          Seek Offset: {}
          Simulated Cycles: {}
          Simulated Packets: {}
          Average injection rate: {:.6f}
          Average injection rate per node: {:.6f}""".format(
                n, r['seek_offset'], r['num_cycles'], r['num_packets'],
                 float(r['num_packets']) / r['num_cycles'],
                 float(r['num_packets']) / r['num_cycles'] / self.hdr['num_nodes']
            )
        self.header += """
  Size of header (B): {}
NT_TRACEFILE---------------------""".format(self.hdr['size'])
        
    def read_regions(self, fh):
        self.hdr['regions'] = []
        regionfmt = "=QQQ"
        Nt_RegionHdr = namedtuple("Nt_RegionHdr",
            "seek_offset num_cycles num_packets")
        for i in range(self.hdr['num_regions']):
            self.hdr['regions'].append(
                Nt_RegionHdr._asdict(
                    Nt_RegionHdr._make(
                        struct.unpack(regionfmt, self.fh.read(
                            struct.calcsize(regionfmt))
                        )
                    )
                )
            )

    def read_header(self, fh):
        hdrfmt = "=If30sBxQQII8x"
        Nt_Header = namedtuple("Nt_Header",
            "magic version benchmark_name num_nodes num_cycles num_packets " +
            "notes_length num_regions"
        )
        self.hdr = Nt_Header._asdict(
            Nt_Header._make(
                struct.unpack(hdrfmt,
                    self.fh.read(struct.calcsize(hdrfmt)))))
        if self.hdr['magic'] != self.MAGIC:
            raise ValueError("Bad magic number in trace file")
        if self.hdr['notes_length'] in xrange(1, self.NOTES_LIMIT):
            self.hdr['notes'] = struct.unpack(
                '={}s'.format(self.hdr['notes_length']),
                self.fh.read(self.hdr['notes_length']))[0]
            self.hdr['notes'].rstrip('\0')
        else:
            self.hdr['notes'] = None
        self.hdr['benchmark_name'] = self.hdr['benchmark_name'].rstrip('\0')

    def open_trace(self, filename):
        types = {
            'application/x-gzip': gzip.GzipFile,
            'application/x-bzip2': bz2.BZ2File,
            'application/octet-stream': open
        }
        ftype = magic.Magic(mime=True).from_file(filename)
        return types[ftype](filename)


if __name__ == "__main__":
    ARGS = docopt(__doc__, version='1.0')
    nt = netrace(ARGS['<trace>'])
    print (nt.header)
    pkt = nt.read_packet()
    while pkt:
        print (pkt)
        pkt = nt.read_packet()
    """ntr = netrace.nt_context(ARGS['<trace.tra.bz2>'])
    netrace.nt_print_trheader(ntr);
    pkt = ntr.read()
    while pkt != None:
        print ("  ID:{} CYC:{} SRC:{} DST:{} ADR:0x{:08x} TYP:{} NDEP:{} {}".format(
            pkt.id, pkt.cycle, pkt.src, pkt.dst, pkt.addr, pkt.type_str,
            pkt.num_deps, ' '.join(map(str,pkt.deps_list))))
        pkt = ntr.read()
    ntr.close()"""

