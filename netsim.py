#!/usr/bin/env python3
"""
    Netsim, a network performance characteriser for Python, using netrace

    Reads a netrace compatible trace file into Python. Output format
    matches that of "trace_viewer <file> -p" from original netrace sample code.

    This version is implemented in native python rather with Swig, to see
    if I'm any better at writing stuff in pure Python.

    Usage:
        netsim.py [options] <trace>

    Options:
        -h --help                       This help text.
        -t type --network-type=type     Type of network to simulate, leave
                                        blank to see options. [default: help]
        -o opts --network-opts=opts     Configuration options for network.
                                        [default: --help]

    Arguments:
        <trace>                     A netrace compatible trace file from (Ge)M5
                                    in bz2, gzip or uncompressed format.

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
from netrace import netrace, netrace_packet
from os.path import isfile
from distutils.util import strtobool
import sys
import json
import inspect
import shlex
import importlib
import math

# TODO: Map different node types into the network (at the start?)


class netsim_basenet:
    """
        WAT
    """
    def __init__(self, argstr):
        argv = shlex.split(argstr)
        self.ARGS = docopt(self.__doc__, argv=argv)
        self.l1d = {}
        self.l1i = {}
        self.l2 = {}
        self.mc = {}

    def build_revidx(self):
        self.l1d_r = {v, k for k, v in self.l1d.items()}
        self.l1i_r = {v, k for k, v in self.l1i.items()}
        self.l2_r = {v, k for k, v in self.l2.items()}
        self.mc_r = {v, k for k, v in self.mc.items()}

    def map_nodes(self, l1, l2, mc):
        raise NotImplementedError

    def attach(self, node_type, node_list):
        raise NotImplementedError


class netsim_benes(netsim_basenet):
    """
        A Benes network based on the MCENoC approach

        Usage:
            NETSIM_ARGS -n num [options]

        Options:
            -h --help                   This help text
            -n num --nodes=num          Number of nodes in system
            -s bits --switchbits=bits   Number of bits per switch
                                        (2**bits ports) [default: 1]
    """
    def __init__(self, argstr):
        super().__init__(argstr)
        nodes = int(self.ARGS['--nodes'])
        channels = 2**math.ceil(math.log2(nodes))
        if channels > nodes:
            print(
                "W: {:d} ports are unused ({:.1f}% waste)".format(
                    channels - nodes, (channels-nodes)/nodes * 100))
        self.nodes = nodes
        self.channels = channels
        self.bits = int(self.ARGS['--switchbits'])
        assert(2**self.bits < self.channels)
        self.ports = 2**self.bits
        # Using my paper, A Benes Based NoC Switching Architecture for
        # Mixed Criticality Embedded Systems
        X = math.ceil(math.log(self.channels, self.ports))
        S = 2*math.log(self.ports**X, self.ports) - 1
        m = math.log2(self.channels / (self.ports**(X-1)))
        self.midbits = m
        self.midports = 2**m

    def map_nodes(self, l1, l2, mc):
        assert(len(l1) == len(l2) == self.nodes)
        # No extravagant mapping in Benes as it's irrelevant.
        for i in l1:
            self.l1d[i] = i
            self.l1i[i] = i
        for i in l2:
            self.l2[i] = i
        for i in mc:
            self.mc[i] = i
        self.build_revidx()


class netsim_mesh(netsim_basenet):
    """
        A fairly boring mesh network

        Nodes are arranged in 2D with cache and memory controllers evenly
        dispersed.

        Usage:
            NETSIM_ARGS -n num [options]

        Options:
            -h --help                   This help text
            -n num --nodes=num          Number of nodes in system
            -d dirs --directions=dirs   Number of directions per switch
                                        [default: 2]
            -b bits --buffering=bits    Amount of buffering per port
                                        [default: 128]
    """
    def __init__(self, argstr):
        super().__init__(argstr)
        self.nodes = int(self.ARGS['--nodes'])
        self.xy = int(math.sqrt(self.nodes))
        assert(self.xy == math.sqrt(self.nodes))
        self.buffering = int(self.ARGS['--buffering'])
        self.directions = int(self.ARGS['--directions'])

    def map_nodes(self, l1, l2, mc):
        assert(len(l1) == len(l2) == self.nodes)
        assert(len(mc) == self.xy)
        x = 0
        y = 0
        for i in range(l1):
            self.l1d[(x, y)] = i
            self.l1i[(x, y)] = i
            # Put the L2 caches adjacent to cores as len()s are equal
            self.l2[(x + 1, y)] = i
            x = x + 2 if x + 2 < self.xy * 2 else 0
            y = y if x else y + 1
            if x + 1 == self.xy * 2:
                # Skip a row in the middle for mem controllers
                x += 1
        y = 0
        for i in range(mc):
            # MCs straight down the middle
            self.mc[(self.xy, y)] = i
        self.build_revidx()


class netsim:
    def __init__(self, nt, **kwargs):
        self.ntrc = nt
        print(kwargs)
        classes = {x.__name__[7:]: x for x in netsim_basenet.__subclasses__()}
        if (kwargs['network_type'] == 'help' or
                kwargs['network_type'] not in classes.keys()):
            print('Available networks: {}'.format(', '.join(classes.keys())))
            sys.exit(0)
        netclass = classes[kwargs['network_type']](kwargs['network_opts'])


if __name__ == "__main__":
    ARGS = docopt('\n'.join(__doc__.split('\n')[:-24]), version='1.0')
    ns = netsim(netrace(ARGS['<trace>']),
                **{k.strip('--').replace('-', '_'):
                v for k, v in ARGS.items()})