#!/usr/bin/env python3
"""
    Netrace for Python

    Reads a netrace compatible trace file into Python. Output format
    matches that of "trace_viewer <file> -p" from original netrace sample code.

    This version is implemented in native python rather with Swig, to see
    if I'm any better at writing stuff in pure Python.

    Usage:
        netrace.py [options] <trace>

    Options:
        -h --help                   This help text.
        -t --print-node-types       Decode node types to strings

    Arguments:
        <trace>                     A netrace compatible trace file from (Ge)M5
                                    in bz2, gzip or uncompressed format.

    Copyright (c) 2010-2011 The University of Texas at Austin
    Copyright (c) 2016 Steve Kerrison, University of Bristol, UK
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met: redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer;
    redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution;
    neither the name of the copyright holders nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from docopt import docopt
import magic  # python-magic, from pypy, not python-magic 5.x from distro repos
import gzip
import bz2
import struct
from collections import namedtuple


class netrace_packet:
    PACKET_TYPES = ["InvalidCmd", "ReadReq", "ReadResp",
                    "ReadRespWithInvalidate", "WriteReq", "WriteResp",
                    "Writeback", "InvalidCmd", "InvalidCmd", "InvalidCmd",
                    "InvalidCmd", "InvalidCmd", "InvalidCmd", "UpgradeReq",
                    "UpgradeResp", "ReadExReq", "ReadExResp", "InvalidCmd",
                    "InvalidCmd", "InvalidCmd", "InvalidCmd", "InvalidCmd",
                    "InvalidCmd", "InvalidCmd", "InvalidCmd",
                    "BadAddressError", "InvalidCmd", "InvalidateReq",
                    "InvalidateResp", "DowngradeReq", "DowngradeResp"]
    PACKET_SIZE = (
        [-1, 8, 72, 72, 72, 8, 72] +
        [None] * 6 +
        [8, 8, 8, 72] +
        [None] * 8 +
        [8, None, 8, 8, 8, 72])

    NODE_TYPES = ["L1D", "L1I", "L2", "M", "Invalid"]

    def __init__(self, data):
        self.data = data
        self.unpack_types()

    def unpack_types(self):
        self.src_type = (self.data.node_types >> 4) & 0xf
        self.dst_type = self.data.node_types & 0xf

    def type_str(self):
        """Similar to __str__ but with node types decoded"""
        return ("  ID:{} CYC:{} SRC:{}-{} DST:{}-{} " +
                "ADR:0x{:08x} TYP:{} NDEP:{} {}").format(
                self.data.id, self.data.cycle, self.NODE_TYPES[self.src_type],
                self.data.src, self.NODE_TYPES[self.dst_type], self.data.dst,
                self.data.addr, self.PACKET_TYPES[self.data.type],
                self.data.num_deps, ' '.join(map(str, self.deps)))

    def __str__(self):
        return ("  ID:{} CYC:{} SRC:{} DST:{} " +
                "ADR:0x{:08x} TYP:{} NDEP:{} {}").format(
                self.data.id, self.data.cycle, self.data.src, self.data.dst,
                self.data.addr, self.PACKET_TYPES[self.data.type],
                self.data.num_deps, ' '.join(map(str, self.deps)))


class netrace:

    MAGIC = 0x484A5455
    NOTES_LIMIT = 8192
    Packet = namedtuple("Packet",
                        "cycle id addr type src dst node_types num_deps")
    PACKET_FORMAT = "QIIBBBBB"
    PACKET_LENGTH = struct.calcsize(PACKET_FORMAT)

    def __init__(self, filename):
        self.fh = self.open_trace(filename)
        self.read_header(self.fh)
        self.read_regions(self.fh)
        self.header_size = self.fh.tell()
        self.header_str()

    def rewind(self):
        """Go back to start of trace (first region, after header)"""
        self.fh.seek(self.header_size)

    def read_packet(self):

        data = self.fh.read(self.PACKET_LENGTH)
        if len(data) != self.PACKET_LENGTH:
            return None
        pkt = self.Packet._make(struct.unpack(self.PACKET_FORMAT, data))
        pkt = netrace_packet(pkt)
        pkt.deps = []
        for i in range(pkt.data.num_deps):
            pkt.deps.append(struct.unpack("I", self.fh.read(4))[0])
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
            self.benchmark_name.decode('ascii'),
            self.hdr.version,
            self.hdr.num_regions,
            self.hdr.num_nodes,
            self.hdr.num_cycles,
            self.hdr.num_packets,
            float(self.hdr.num_packets) / self.hdr.num_cycles,
            self.notes.decode('ascii')
        )
        for n, r in enumerate(self.regions):
            if r.num_cycles:
                air = "{:.6f}".format(float(r.num_packets) / r.num_cycles)
                airn = "{:.6f}".format(
                    float(r.num_packets) / r.num_cycles / self.hdr.num_nodes)
            else:
                air = "N/A"
                airn = "N/A"
            self.header += """
        Region {}:
          Seek Offset: {}
          Simulated Cycles: {}
          Simulated Packets: {}
          Average injection rate: {}
          Average injection rate per node: {}""".format(
                n, r.seek_offset, r.num_cycles, r.num_packets, air, airn
            )
        self.header += """
  Size of header (B): {}
NT_TRACEFILE---------------------""".format(self.header_size)

    def read_regions(self, fh):
        self.regions = []
        regionfmt = "=QQQ"
        Nt_RegionHdr = namedtuple("Nt_RegionHdr",
                                  "seek_offset num_cycles num_packets")
        for i in range(self.hdr.num_regions):
            self.regions.append(
                Nt_RegionHdr._make(
                    struct.unpack(regionfmt, self.fh.read(
                        struct.calcsize(regionfmt))
                    )
                )
            )

    def read_header(self, fh):
        hdrfmt = "=If30sBxQQII8x"
        Nt_Header = namedtuple("Nt_Header",
                               "magic version benchmark_name num_nodes " +
                               "num_cycles num_packets notes_length " +
                               "num_regions")
        self.hdr = Nt_Header._make(
            struct.unpack(hdrfmt,
                          self.fh.read(struct.calcsize(hdrfmt))))
        if self.hdr.magic != self.MAGIC:
            raise ValueError("Bad magic number in trace file")
        if self.hdr.notes_length in range(1, self.NOTES_LIMIT):
            self.notes = struct.unpack(
                '={}s'.format(self.hdr.notes_length),
                self.fh.read(self.hdr.notes_length))[0]
            self.notes = self.notes.rstrip(b'\0')
        else:
            self.notes = None
        self.benchmark_name = self.hdr.benchmark_name.rstrip(b'\0')

    def open_trace(self, filename):
        types = {
            'application/x-gzip': gzip.GzipFile,
            'application/x-bzip2': bz2.BZ2File,
            'application/octet-stream': open
        }
        ftype = magic.Magic(mime=True).from_file(filename)
        return types[ftype](filename)


if __name__ == "__main__":
    ARGS = docopt('\n'.join(__doc__.split('\n')[:-24]), version='1.0')
    nt = netrace(ARGS['<trace>'])
    print(nt.header)
    pkt = nt.read_packet()
    while pkt:
        if ARGS['--print-node-types']:
            print(pkt.type_str())
        else:
            print(pkt)
        pkt = nt.read_packet()
