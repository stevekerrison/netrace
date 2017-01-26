#!/usr/bin/env python3
"""
    Netsim, a network performance characteriser for Python, using netrace

    Reads a netrace compatible trace file into Python. Output format
    matches that of "trace_viewer <file> -p" from original netrace sample code.

    This version is implemented in native python rather with Swig, to see
    if I'm any better at writing stuff in pure Python.

    Usage:
        netsim.py [options] <trace>
        netsim.py map <trace>

    In map mode <trace>.map is created, which can then be used to speed up
    normal mode.

    Options:
        -h --help                       This help text.
        -t type --network-type=type     Type of network to simulate, leave
                                        blank to see options. [default: help]
        -o opts --network-opts=opts     Configuration options for network.
                                        [default: --help]
        -c mc --mem-controllers=mc      Number of memory controllers to
                                        provide. Uses sqrt of number of nodes
                                        by default [default: None].
        -p --progress                   Print progress to stderr
        -l n --packet-limit=n           Process no more than n packets.
        -r reg --region=reg             Region to simulate [default: all]

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
from collections import deque
import sys
import json
import inspect
import shlex
import importlib
import math
import pickle
import time


class netsim_network:
    """
        A network of netsim_nodes.

        Nodes can be looked up via their netrace (type,id) tuple, or by
        their positional data from their particular subclass of netsim_basenet
    """
    def __setitem__(self, key, value):
        if key in self or value in self:
            raise KeyError("Cannot change mapping of existing entry")
        super().__setitem__(self, key, value)
        super().__setitem__(self, value, key)


class netsim_node:
    """
        Node type for netsim / netrace
    """

    # Type 4 (unknown / None) can be used for routers
    TNUM_TSTR = {0: 'l1d', 1: 'l1i', 2: 'l2', 3: 'mc', 4: None}
    TSTR_TNUM = {v: k for k, v in TNUM_TSTR.items()}

    @staticmethod
    def src_from_packet(packet):
        return (packet.src_type, packet.data.src)

    @staticmethod
    def dst_from_packet(packet):
        return (packet.dst_type, packet.data.dst)

    def __init__(self, netrace_id, netsim_position, queues=['recv']):
        if not isinstance(netrace_id, tuple) or len(netrace_id) != 2:
            raise KeyError("netrace_id must be a tuple of (typestr, nodeid)")
        if netrace_id[0] not in self.TSTR_TNUM:
            raise KeyError("Node type {} for node ID {} unknown".format(
                           netrace_id[0], netrace_id[1]))
        if not isinstance(netrace_id[1], int):
            raise KeyError("Node ID '{}' not an integer".format(netrace_id[1]))
        # Use numerical type IDs after instantiation for efficiency
        self.nid = (self.TSTR_TNUM[netrace_id[0]], netrace_id[1])
        self.pos = netsim_position
        self.q = {n: deque() for n in queues}
        self.active = {}
        self.cycle_adj = 0
        self.rate = sys.maxsize


class netsim_route:
    """
        Track data from a packet as it moves between nodes
    """
    def __init__(self, pkt, src, dst, net):
        self.pkt = pkt
        self.net = net
        self.dst = dst
        self.nodes = {src: pkt.PACKET_SIZE[pkt.data.type]}
        self.queues = []
        self.chain = [src]      # Active part of the route
        self.injected = False
        self.start = 0
        self.end = 0

    def head(self):
        """
            Determine next node that we will need to open a route to and its
            target queue
        """
        if self.end < len(self.chain) - 1:
            return (self.queues[self.end], self.chain[self.end + 1])
        else:
            return None

    def open(self, node):
        """
            Add path along the route
        """
        """print("Opening from {} to {} for {}".format(self.chain[self.end].pos,
                                             self.chain[self.end+1].pos,
                                             self.pkt.data.id))"""
        self.nodes[node] = 0
        self.end += 1

    def plan(self, node, queue="recv"):
        if not isinstance(node, netsim_node):
            raise ValueError("Node not provided")
        if node in self.nodes:
            raise KeyError("Node already registered for this packet")
        if queue is None:
            raise ValueError("None type queue provided")
        self.nodes[node] = None
        self.chain.append(node)
        self.queues.append(queue)

    def propagate(self):
        """
            Move data along route, throttled by nodes. Returns nodes that have
            sent all data so the network simulator can purge queues.
        """
        if self.start > self.end:
            raise RuntimeError("Route start is after its end!?")
        elif self.start == self.end:
            if len(self.chain) == 1:
                # Self-reference (probably invalidation req) so clean up now
                self.nodes[self.chain[-1]] = 0
                return [(self.chain[-1], self.pkt)]
            else:
                # Nothing can progress right now
                pass
        else:
            for (s, d) in zip(
                    reversed(self.chain[self.start:self.end]),
                    reversed(self.chain[self.start+1:self.end+1])):
                # Rate limit, or transfer all available data if no rate set
                rate = min(s.rate, self.nodes[s])
                if rate == 0:
                    raise ValueError("Zero rate encountered", self)
                self.nodes[s] -= rate
                self.nodes[d] += rate
        closed = []
        for n in self.chain[self.start:self.end]:
            if self.nodes[n]:
                # Cannot close tail beyond this point as data still exists
                break
            else:
                # All data shifted, so close the tail a little...
                self.start += 1
                closed.append((n, self.pkt))
        if self.start == self.end and self.end == len(self.chain) - 1:
            # All data reached receiver
            closed.append((self.chain[-1], self.pkt))
        return closed

    def __len__(self):
        """Return the number of bytes still in transit"""
        if self.end == len(self.chain) - 1:
            """All data is at receiver node now"""
            return 0
        return sum([self.nodes[n] for n in self.chain[self.start:self.end+1]])

    def __str__(self):
        """Try to depict a route sensibly"""
        strs = []
        for n in self.chain:
            strs.append("""{}: {}""".format(n.pos, self.nodes[n]))
        return "{}:{}s{}e{}::".format(self.pkt.data.id, len(self), self.start,
                                      self.end) + ' -> '.join(strs)

    def __repr__(self):
        return self.__str__()


class netsim_basenet:
    """
        Base class for netsim networks

        Doesn't possess sufficient logic to simulate on its own
    """

    def __init__(self, argstr, num_nodes):
        argv = shlex.split(argstr)
        self.ARGS = docopt(self.__doc__, argv=argv)
        self.num_nodes = num_nodes
        self.bypos = {}
        self.bynid = {}
        self.active_nodes = set()
        self.nodes = []
        self.dispatchable = {}
        self.packets = {}
        self.delaycache = {}
        self.routes = {}
        self.dependencies = {}
        self.cycle = 0

    def add_node(self, node):
        pos = node.pos
        nid = node.nid
        if pos in self.bypos:
            raise KeyError("Node position '{}' already in use".format(pos))
        if nid in self.bynid:
            raise KeyError("Node with ID '{}' already in system".format(nid))
        self.nodes.append(node)
        self.bypos[pos] = node
        self.bynid[nid] = node

    def map_nodes(self, mapping):
        raise NotImplementedError

    def attach(self, node_type, node_list):
        raise NotImplementedError

    def register(self, pkt):
        """Register a packet which will be injected now or in the future"""
        pkt.cycle_adj = 0
        self.packets[pkt.data.id] = pkt
        if (self.cycle in self.dispatchable and pkt.data.id in
                self.dispatchable[self.cycle]):
            raise RuntimeError(
                "Packet {} marked for dispatch before registration".format(
                    pkt.data.id))
        # A packet is immediately dispatchable if its dependencies have already
        # completed, or it has no dependencies.
        if pkt.data.id not in self.dependencies:
            # Dependencies may have cleared already, but imposed a delay
            if pkt.data.id in self.delaycache:
                cycle = pkt.data.cycle + self.delaycache[pkt.data.id]
                del self.delaycache[pkt.data.id]
            else:
                cycle = pkt.data.cycle
            self.mark_dispatch(cycle, pkt.data.id)
        for dep in pkt.deps:
            if dep not in self.dependencies:
                self.dependencies[dep] = set()
            self.dependencies[dep].add(pkt)
            self.update_delaycache(dep, 0)
        # Create route tracking for packet
        src = netsim_node.src_from_packet(pkt)
        dst = netsim_node.dst_from_packet(pkt)
        self.routes[pkt] = netsim_route(
            pkt, self.bynid[src], self.bynid[dst], self)

    def update_delaycache(self, pktid, delay):
        was = None if pktid not in self.delaycache else self.delaycache[pktid]
        if was is None or delay > was:
            self.delaycache[pktid] = delay

    def mark_dispatch(self, cycle, pktid):
        if cycle not in self.dispatchable:
            self.dispatchable[cycle] = set()
        if cycle < self.cycle:
            raise RuntimeError(
                "Packet {} being dispatched at {} when now is {}".format(
                    pktid, cycle, self.cycle))
        if pktid in self.dispatchable[cycle]:
            raise RuntimeError(
                "Packet {} already in dispatch table".format(pktid))
        self.dispatchable[cycle].add(pktid)

    def inject(self, pkt):
        """Inject a packet into the network"""
        raise NotImplementedError

    def clear(self, closures):
        """
            Clear queues and, when packets can be cleared, clean up historic
            dependencies. Must be implemented by child class.
        """
        raise NotImplementedError

    def step(self):
        """
            Step the network simulation forward by one cycle

            Must be implemented by subclass
        """
        raise NotImplementedError


class netsim_zero(netsim_basenet):
    """
        An idealised zero-delay network with no contention except at
        {in|e}gress of nodes. A packet arrives in the receiver queue
        in one cycle, regardless of size. A queue entry can be removed
        every cycle.

        Explicitly provide an empty option string (-o" ") to netsim in order
        to utilize this skeleton network.

        Usage:
            NETSIM_ARGS [options]

        Options:
            -h --help                   This help text
    """
    def __init__(self, argstr, num_nodes):
        super().__init__(argstr, num_nodes)

    def map_nodes(self, mapping):
        tdec = netsim_node.TSTR_TNUM
        l1 = mapping[tdec['l1i']]
        l2 = mapping[tdec['l2']]
        mc = mapping[tdec['mc']]
        if len(l1) != len(l2) != self.num_nodes:
            raise ValueError("Expected number of L1/L2 to equal node count")
        pos = 0
        for nodeid in l1:
            nid = ('l1d', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1
        for nodeid in l1:
            nid = ('l1i', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1
        for nodeid in l2:
            nid = ('l2', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1
        for nodeid in mc:
            nid = ('mc', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1

    def route(self, pkt, node):
        if not len(node.active) and not len(node.q['recv']):
            self.active_nodes.add(node)
        node.q['recv'].appendleft(pkt)
        if (
                netsim_node.dst_from_packet(pkt) !=
                netsim_node.src_from_packet(pkt)):
            # Invalidation requests appear as self-messages. Avoid cycle.
            self.routes[pkt].open(node)
            self.routes[pkt].injected = True
            # Move all data to receiver straight away
            self.routes[pkt].propagate()

    def inject(self, pkt):
        """Start routing packet"""
        pkt.cycle_adj = self.cycle - pkt.data.cycle
        # Zero network opens route to destination instantly
        if (netsim_node.dst_from_packet(pkt) !=
                netsim_node.src_from_packet(pkt)):
            self.routes[pkt].plan(self.bynid[netsim_node.dst_from_packet(pkt)])
        self.route(pkt, self.bynid[netsim_node.dst_from_packet(pkt)])

    def clear(self, closures):
        for node, pkt in closures:
            if pkt not in node.active:
                raise RuntimeError(
                    "Packet {} was expected to be active on node {}".format(
                        pkt.data.id, node))
            del node.active[pkt]
            if not len(node.active) and not len(node.q['recv']):
                self.active_nodes.remove(node)
            # If packet has sent all data, so clean up
            if not len(self.routes[pkt]):
                # Check if dependent packets can be dispatched now
                for dep in pkt.deps:
                    self.update_delaycache(dep, self.cycle - pkt.data.cycle)
                    if (
                            len(self.dependencies[dep]) == 1 and dep in
                            self.packets):
                        # All deps cleared, so the packet is dispatchable, and
                        # already exists, so must be registered and waiting.
                        self.mark_dispatch(self.packets[dep].data.cycle +
                                           self.delaycache[dep], dep)
                    # This dependency reference is no longer needed
                    self.dependencies[dep].remove(pkt)
                    if len(self.dependencies[dep]) == 0:
                        del self.dependencies[dep]
                if self.cycle <= pkt.data.cycle:
                    raise RuntimeError((
                        "Packet {} clearing at {}, which is contradictory " +
                        "to its original trace cycle of {}").format(
                            pkt.data.id, self.cycle, pkt.data.cycle))
                # Route is no longer needed
                del self.routes[pkt]
                # Packet is no longer needed
                del self.packets[pkt.data.id]
                if pkt.data.id in self.dependencies:
                    del self.dependencies[pkt.data.id]
                if pkt.data.id in self.delaycache:
                    del self.delaycache[pkt.data.id]

    def step(self):
        """
            Progress each packet. In a zero network this is easy... just
            take one item off each node's receive queue. Also inject packets
            that can now be dispatched.
        """
        closures = []
        for n in self.active_nodes:
            if len(n.active) > 1:
                raise RuntimeError(
                    "Node {} handling simultaneous receives".format(n))
            elif len(n.active) == 1:
                pkt, q = n.active.popitem()
                closures += self.routes[pkt].propagate()
            elif len(n.q['recv']):
                # We're not active but can be
                pkt = n.q['recv'].pop()
                n.active[pkt] = None
                closures += self.routes[pkt].propagate()
        self.clear(closures)
        if self.cycle in self.dispatchable:
            for pktid in self.dispatchable[self.cycle]:
                self.inject(self.packets[pktid])
            del self.dispatchable[self.cycle]


class netsim_benes_simple(netsim_zero):
    """
        A simplified Benes abstraction based off the zero-network
        implementation.

        Latency is defined as an option, so the user must determine their
        switch characteristics themselves.

        We assume that routing was revolved statically. TDM phases and their
        overhead are approximated in relation to the size of packets sent.

        Usage:
            NETSIM_ARGS [options]

        Options:
            -h --help               This help text
            -r=rate --rate=rate     Transmission rate (bytes/cyc) [default: 8]
            -l=n --latency=n        Src-to-dst latency of n cycles [default: 5]
            -t=n --tdm=n            Cycle length of TDM phases. If n is less
                                    than max(netrace_packet.PACKET_SIZE)/rate,
                                    then extra overhead is added to transfers
                                    to account for repeated headers sent for a
                                    single packet. If n is equal or greater,
                                    there will be significant slack periods for
                                    many or all transfers. Default is max
                                    packet size.
    """
    def __init__(self, argstr, num_nodes):
        super().__init__(argstr, num_nodes)
        self.latency = int(self.ARGS['--latency'])
        self.rate = int(self.ARGS['--rate'])
        if self.ARGS['--tdm']:
            self.tdm = int(self.ARGS['--tdm'])
        else:
            self.tdm = math.ceil((
                self.latency +
                max(filter(None.__ne__, netrace_packet.PACKET_SIZE)) /
                self.rate))

    def register(self, pkt):
        """
            Register a packet which will be injected now or in the future,
            enforcing TDM alignment
        """
        pkt.cycle_adj = 0
        self.packets[pkt.data.id] = pkt
        if (self.cycle in self.dispatchable and pkt.data.id in
                self.dispatchable[self.cycle]):
            raise RuntimeError(
                "Packet {} marked for dispatch before registration".format(
                    pkt.data.id))
        # A packet is immediately dispatchable if its dependencies have already
        # completed, or it has no dependencies.
        if pkt.data.id not in self.dependencies:
            # Dependencies may have cleared already, but imposed a delay
            if pkt.data.id in self.delaycache:
                cycle = pkt.data.cycle + self.delaycache[pkt.data.id]
                del self.delaycache[pkt.data.id]
            else:
                cycle = pkt.data.cycle
            cycle += cycle % self.tdm
            self.mark_dispatch(cycle, pkt.data.id)
        for dep in pkt.deps:
            if dep not in self.dependencies:
                self.dependencies[dep] = set()
            self.dependencies[dep].add(pkt)
            self.update_delaycache(dep, 0)
        # Create route tracking for packet
        src = netsim_node.src_from_packet(pkt)
        dst = netsim_node.dst_from_packet(pkt)
        self.routes[pkt] = netsim_route(
            pkt, self.bynid[src], self.bynid[dst], self)

    def inject(self, pkt):
        super().inject(pkt)
        r = self.routes[pkt]
        ncyc = self.latency + math.ceil(len(r) / self.rate)
        if ncyc > self.tdm:
            chunk = ((ncyc - self.tdm) - self.latency) * self.rate
            chunks = len(r) / chunk
            overhead = (self.latency * self.rate) * (chunks - 1)
            r.chain[netsim_node.src_from_packet(pkt)] += overhead

    def clear(self, closures):
        for node, pkt in closures:
            if pkt not in node.active:
                raise RuntimeError(
                    "Packet {} was expected to be active on node {}".format(
                        pkt.data.id, node))
            del node.active[pkt]
            if not len(node.active) and not len(node.q['recv']):
                self.active_nodes.remove(node)
            # If packet has sent all data, so clean up
            if not len(self.routes[pkt]):
                # Check if dependent packets can be dispatched now
                for dep in pkt.deps:
                    cycle = self.cycle - pkt.data.cycle
                    cycle += cycle % self.tdm
                    self.update_delaycache(dep, cycle)
                    if (
                            len(self.dependencies[dep]) == 1 and dep in
                            self.packets):
                        # All deps cleared, so the packet is dispatchable, and
                        # already exists, so must be registered and waiting.
                        cycle = (self.packets[dep].data.cycle +
                                 self.delaycache[dep])
                        cycle += cycle % self.tdm
                        self.mark_dispatch(cycle, dep)
                    # This dependency reference is no longer needed
                    self.dependencies[dep].remove(pkt)
                    if len(self.dependencies[dep]) == 0:
                        del self.dependencies[dep]
                if self.cycle <= pkt.data.cycle:
                    raise RuntimeError((
                        "Packet {} clearing at {}, which is contradictory " +
                        "to its original trace cycle of {}").format(
                            pkt.data.id, self.cycle, pkt.data.cycle))
                """print(
                    "Retiring {} ORIG:{}, NOW:{}".format(pkt.data.id,
                                                         pkt.data.cycle,
                                                         self.cycle))"""
                # Route is no longer needed
                del self.routes[pkt]
                # Packet is no longer needed
                del self.packets[pkt.data.id]
                if pkt.data.id in self.dependencies:
                    del self.dependencies[pkt.data.id]
                if pkt.data.id in self.delaycache:
                    del self.delaycache[pkt.data.id]


class netsim_benes(netsim_basenet):
    """
        A Benes network based on the MCENoC approach

        Usage:
            NETSIM_ARGS [options]

        Options:
            -h --help                   This help text
            -s bits --switchbits=bits   Number of bits per switch
                                        (2**bits ports) [default: 1]
    """
    def __init__(self, argstr, num_nodes):
        super().__init__(argstr, num_nodes)
        channels = 2**math.ceil(math.log2(num_nodes))
        if channels > num_nodes:
            print(
                "W: {:d} ports are unused ({:.1f}% waste)".format(
                    channels - nodes, (channels-num_nodes)/num_nodes * 100))
        self.channels = channels
        self.bits = int(self.ARGS['--switchbits'])
        if 2**self.bits >= self.channels:
            raise ValueError(
                "Network of {} bits cannot accommodate {} channels".format(
                    self.bits, self.channels))
        self.ports = 2**self.bits
        # Using my paper, A Benes Based NoC Switching Architecture for
        # Mixed Criticality Embedded Systems
        X = math.ceil(math.log(self.channels, self.ports))
        S = 2*math.log(self.ports**X, self.ports) - 1
        m = math.log2(self.channels / (self.ports**(X-1)))
        self.midbits = m
        self.midports = 2**m

    def map_nodes(self, mapping):
        tdec = netsim_node.TSTR_TNUM
        l1 = mapping[tdec['l1i']]
        l2 = mapping[tdec['l2']]
        mc = mapping[tdec['mc']]
        assert(len(l1) == len(l2) == self.num_nodes)
        # No extravagant mapping in Benes as it's irrelevant.
        pos = 0
        for nodeid in l1:
            nid = ('l1d', nodeid)
            self.add_node(netsim_node(nid, pos))
            nid = ('l1i', nodeid)
            self.add_node(netsim_node(nid, pos + 1))
            pos += 2
        for nodeid in l2:
            nid = ('l2', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1
        for nodeid in mc:
            nid = ('mc', nodeid)
            self.add_node(netsim_node(nid, pos))
            pos += 1


class netsim_mesh(netsim_basenet):
    """
        A fairly boring mesh network

        Nodes are arranged in 2D with cache and memory controllers evenly
        dispersed.

        Usage:
            NETSIM_ARGS [options]

        Options:
            -h --help                   This help text
            -d dims --dimensions=dims   Number of dimensions in which the mesh
                                        can be traversed. Range: 2--4.
                                        [default: 2]
            -b bits --buffering=bits    Amount of buffering per port
                                        [default: 128]
            -r rate --rate=rate         Link rate (bytes/cyc) [default: 4]
    """
    class switch(netsim_node):
        """
            Special sublcass of netsim_node that provide routing for
            mesh networks.
        """
        def __init__(self, netrace_id, netsim_position, dimensions):
            self.dimensions = dimensions
            if dimensions not in range(2, 5):
                raise ValueError(
                    "Switch cannot have {} dimensions".format(dimensions))
            dirs = ['l', 'r', 't', 'b', 'br', 'tl', 'bl', 'tr'][:2*dimensions]
            super().__init__(netrace_id, netsim_position,
                             dirs +
                             ['l1d', 'l1i', 'l2', 'mc'])

    def __init__(self, argstr, num_nodes):
        super().__init__(argstr, num_nodes)
        self.xy = int(math.sqrt(self.num_nodes))
        if self.xy != math.sqrt(self.num_nodes):
            raise ValueError(
                "{} nodes does not a square make".format(self.num_nodes))
        self.buffering = int(self.ARGS['--buffering'])
        self.dimensions = int(self.ARGS['--dimensions'])
        if self.dimensions not in range(2, 5):
            raise ValueError(
                "Cannot have {} dimensions".format(self.dimensions))

    def register(self, pkt):
        """
            A route is pre-calculated, following a dimension order routing
            strategy of:
                L -> NE/SW* -> NW/SE* -> N/S -> W/E -> L

            Diagonal dimensions only available if sufficient dimensions
            specified.
        """
        # No normal registration
        super().register(pkt)
        self.routes[pkt].rate = int(self.ARGS['--rate'])
        # Plan the packet's route
        sposfull = self.bynid[netsim_node.src_from_packet(pkt)].pos
        dposfull = self.bynid[netsim_node.dst_from_packet(pkt)].pos
        srctype = netsim_node.TNUM_TSTR[sposfull[2]]
        dsttype = netsim_node.TNUM_TSTR[dposfull[2]]
        spos = sposfull[:2]
        dpos = dposfull[:2]
        route = self.routes[pkt]
        if dposfull != sposfull and sposfull[2] != 4:
            # Get to the switch
            node = self.bypos[(spos[0], spos[1], 4)]
            route.plan(node, srctype)
        while spos != dpos:
            dimelms = list(zip(spos, dpos))
            if self.dimensions >= 4 and (all(
                    d[0] > d[1] for d in dimelms) or all(
                        d[0] < d[1] for d in dimelms)):
                # Diagonal positioning (NE/SW) if enough dimensions defined
                if spos[0] > dpos[0]:
                    spos = (spos[0] - 1, spos[1] - 1)
                    ingress = 'tr'
                else:
                    spos = (spos[0] + 1, spos[1] + 1)
                    ingress = 'bl'
            elif self.dimensions >= 3 and all(
                    d[0] != d[1] for d in dimelms):
                # Diagonal positioning (NW/SE) if enough dimensions defined
                if spos[0] > dpos[0]:
                    spos = (spos[0] - 1, spos[1] + 1)
                    ingress = 'tl'
                else:
                    spos = (spos[0] + 1, spos[1] - 1)
                    ingress = 'br'
            elif dimelms[1][0] != dimelms[1][1]:
                # Vertical dimension
                if spos[1] > dpos[1]:
                    spos = (spos[0], spos[1] - 1)
                    ingress = 't'
                else:
                    spos = (spos[0], spos[1] + 1)
                    ingress = 'b'
            elif dimelms[0][0] != dimelms[0][1]:
                # Horizontal dimension
                if spos[0] > dpos[0]:
                    spos = (spos[0] - 1, spos[1])
                    ingress = 'r'
                else:
                    spos = (spos[0] + 1, spos[1])
                    ingress = 'l'
            route.plan(self.bypos[tuple(list(spos) + [4])], ingress)
        if sposfull != dposfull:
            route.plan(self.bypos[dposfull], 'recv')

    def route(self, pkt, dst):
        """
            Dimension-order wormhole routing towards destination.
            A new hop opens only once the inbound step becomes active
        """
        q, node = dst
        node.q[q].appendleft(pkt)

    def inject(self, pkt):
        """
            Packet can now proceed if network is available
        """
        # print(pkt)
        pkt.cycle_adj = self.cycle - pkt.data.cycle
        self.routes[pkt].injected = True
        node = None
        if (netsim_node.dst_from_packet(pkt) !=
                netsim_node.src_from_packet(pkt)):
            r = self.routes[pkt].head()
            if r is None:
                raise ValueError(netsim_node.src_from_packet(pkt),
                                 netsim_node.dst_from_packet(pkt), r, str(pkt))
            q, node = r
            self.route(pkt, (q, node))
        else:
            # Cheat a bit on self-referencing comms
            node = self.routes[pkt].chain[0]
            self.route(pkt, ('recv', node))
        if node not in self.active_nodes:
            self.active_nodes.add(node)

        """ print(path)
        for n in self.routes[pkt].chain:
            print(pkt.data.id, n.pos, self.routes[pkt].nodes[n]) """

    def map_nodes(self, mapping):
        tdec = netsim_node.TSTR_TNUM
        l1 = mapping[tdec['l1i']]
        l2 = mapping[tdec['l2']]
        mc = mapping[tdec['mc']]
        if len(l1) != len(l2) != self.num_nodes:
            raise ValueError("Expected number of L1/L2 to equal node count")
        if len(mc) != self.xy:
            raise ValueError("Expected {} MCs, got {}".format(len(mc),
                                                              self.xy))
        if not (l1 == l2):
            raise ValueError("Expected list of l1 and l2 IDs to be same")
        # TODO: Better mapping, or more options?
        x = 0
        y = 0
        # Network is a single layer of routers, each with L2, L1D and L1I,
        # and some with a mem controller. Z address indicates destination type.
        tdec = netsim_node.TSTR_TNUM
        # Add endpoints that exist everywhere
        for nodeid in l1:
            nid = ('l1d', nodeid)
            self.add_node(netsim_node(nid, (x, y, tdec['l1d'])))
            nid = ('l1i', nodeid)
            self.add_node(netsim_node(nid, (x, y, tdec['l1i'])))
            nid = ('l2', nodeid)
            self.add_node(netsim_node(nid, (x, y, tdec['l2'])))
            nid = (None, nodeid)
            self.add_node(self.switch(nid, (x, y, tdec[None]),
                                      self.dimensions))
            x += 1
            if x % self.xy == 0:
                y += 1
                x = 0
        # Add MCs in a "diamond" configuration
        if len(mc) != 8:
            raise NotImplementedError("Currently only 8 MCs supported")
        mcpos = [x + (tdec['mc'],) for x in
                 [(3, 2), (4, 2), (2, 3), (5, 3),
                  (2, 4), (5, 4), (3, 5), (4, 5)]]
        for nodeid in mc:
            nid = ('mc', nodeid)
            self.add_node(netsim_node(nid, mcpos.pop(0)))

    def step(self):
        """
            Try to progress packets.

            In a mesh network, this involves progressing routes, resolving
            priorities at switches, and injecting new packets.
        """
        closures = []
        opens = set()
        newactive = set()
        progressable_packets = set()
        # print(self.cycle)
        for n in self.active_nodes:
            # print(n.pos)
            # First process active queues
            dirs = set(n.q.keys())
            if len(n.active) > self.dimensions * 2 + 4:
                raise RuntimeError(
                    "Node {} handling more than {} simultaneous routes".format(
                        n.pos, self.dimensions * 2 + 4))
            for pkt, d in n.active.items():
                # These have active routes, propagate later
                progressable_packets.add(pkt)
                dirs.remove(d)
            for d in dirs:
                if len(n.q[d]):
                    pkt = n.q[d].pop()
                    n.active[pkt] = d
                    self.routes[pkt].open(n)
                    progressable_packets.add(pkt)
                    opens.add(pkt)
        for pkt in opens:
            head = self.routes[pkt].head()
            if head:
                self.route(pkt, head)
                node = head[1]
                if node not in self.active_nodes:
                    newactive.add(node)
        for pkt in progressable_packets:
            closures += self.routes[pkt].propagate()
        """for r in self.routes.values():
            if r.injected:
                print(r)"""
        self.clear(closures)
        self.active_nodes |= newactive
        if self.cycle in self.dispatchable:
            for pktid in self.dispatchable[self.cycle]:
                self.inject(self.packets[pktid])
            del self.dispatchable[self.cycle]

    def clear(self, closures):
        finpkts = set()
        for node, pkt in closures:
            # print("Close: {}, {}".format(node.pos, pkt.data.id))
            if (netsim_node.src_from_packet(pkt) == node.nid and
                    len(self.routes[pkt]) > 1):
                # No queue used at the sender
                continue
            if pkt not in node.active:
                raise RuntimeError(
                    "Packet {} was expected to be active on node {}".format(
                        pkt.data.id, node.pos))
            del node.active[pkt]
            if not len(node.active) and not (
                    sum(map(len, [q for q in node.q.values()]))):
                self.active_nodes.remove(node)
            if not len(self.routes[pkt]):
                finpkts.add(pkt)
        for pkt in finpkts:
            # Check if dependent packets can be dispatched now
            for dep in pkt.deps:
                self.update_delaycache(dep, self.cycle - pkt.data.cycle)
                if (
                        len(self.dependencies[dep]) == 1 and dep in
                        self.packets):
                    # All deps cleared, so the packet is dispatchable, and
                    # already exists, so must be registered and waiting.
                    self.mark_dispatch(self.packets[dep].data.cycle +
                                       self.delaycache[dep], dep)
                # This dependency reference is no longer needed
                self.dependencies[dep].remove(pkt)
                if len(self.dependencies[dep]) == 0:
                    del self.dependencies[dep]
            if self.cycle <= pkt.data.cycle:
                raise RuntimeError((
                    "Packet {} clearing at {}, which is contradictory " +
                    "to its original trace cycle of {}").format(
                        pkt.data.id, self.cycle, pkt.data.cycle))
            """print(
                "Retiring {} ORIG:{}, NOW:{}".format(pkt.data.id,
                                                     pkt.data.cycle,
                                                     self.cycle))"""
            # Route is no longer needed
            del self.routes[pkt]
            # Packet is no longer needed
            del self.packets[pkt.data.id]
            if pkt.data.id in self.dependencies:
                del self.dependencies[pkt.data.id]
            if pkt.data.id in self.delaycache:
                del self.delaycache[pkt.data.id]


class netsim:
    def gather_nodes(self, cache=None, write=False, mc=None):
        """
            Read netrace until we've seen as many nodes and memory controllers
            as we expect, or retrieve known node list from cache
        """
        if mc == "None":
            mc = None
        tdec = netsim_node.TSTR_TNUM
        expect_l1 = self.ntrc.hdr.num_nodes
        expect_l2 = self.ntrc.hdr.num_nodes
        expect_mc = mc if mc else int(math.sqrt(self.ntrc.hdr.num_nodes))
        if cache and not write and isfile(cache):
            with open(cache, 'rb') as f:
                mapping = pickle.load(f)
            # Some checks on the sanity of the mapping
            if len(mapping[tdec['l1i']]) != expect_l1:
                raise ValueError("Cache has {} cores, wanted {}".format(
                    len(mapping[tdec['l1i']]), expect_l1))
            if mapping[tdec['l1i']] != mapping[tdec['l1d']]:
                raise ValueError("L1 I and D maps not equal")
            if mapping[tdec['l1d']] != mapping[tdec['l2']]:
                raise ValueError("Expected an L2 cache bank per L1")
            if len(mapping[tdec['mc']]) != expect_mc:
                raise ValueError("Mismatched number of MCs in cache/sys")
            # Ensure maps are sorted
            for m in mapping:
                mapping[m] = sorted(mapping[m])
            return mapping
        mapping = {
            tdec['l1i']: set(),
            tdec['l1d']: set(),
            tdec['l2']: set(),
            tdec['mc']: set()
        }
        while not (
                   len(mapping[tdec['l1i']]) == expect_l1 and
                   len(mapping[tdec['l1d']]) == expect_l1 and
                   len(mapping[tdec['l2']]) == expect_l2 and
                   len(mapping[tdec['mc']]) == expect_mc):
            pkt = self.ntrc.read_packet()
            if not pkt:
                raise EOFError("Got to end of file before gathering all nodes")
            srcnode = (pkt.src_type, pkt.data.src)
            for loc in ['src', 'dst']:
                if getattr(pkt.data, loc) not in mapping[getattr(pkt, loc +
                                                                 '_type')]:
                    if getattr(pkt, loc + '_type') in [tdec['l1i'],
                                                       tdec['l1d']]:
                        mapping[tdec['l1i']].add(getattr(pkt.data, loc))
                        mapping[tdec['l1d']].add(getattr(pkt.data, loc))
                    else:
                        mapping[getattr(pkt, loc + '_type')].add(
                            getattr(pkt.data, loc))
        if cache and write:
            with open(cache, 'wb') as f:
                pickle.dump(mapping, f, pickle.HIGHEST_PROTOCOL)
        # Allow resumption of simulation after a scan for nodes
        self.ntrc.rewind()
        # Ensure maps are sorted
        for m in mapping:
            mapping[m] = sorted(mapping[m])
        return mapping

    def map(self):
        tf = self.kwargs['<trace>'] + ".map"
        result = self.gather_nodes(tf, True, self.kwargs['mem_controllers'])
        print("Scanned and cached {} nodes, saved to '{}'".format(
              len(result[netsim_node.TSTR_TNUM['l1i']]), tf))

    def step(self, target_cycle):
        while self.network.cycle < target_cycle:
            self.network.step()
            self.network.cycle += 1

    def drain(self):
        """Step network until no more pending packets"""
        while len(self.network.packets):
            self.step(self.network.cycle + 1)

    def progress(self):
        num_packets = self.ntrc.hdr.num_packets
        if self.limit:
            num_packets = self.ntrc.regions[self.kwargs['region']].num_packets
        print((
            "\33[2K\r{:03.02f}%, packet {}/{}, cycle {}, tracking {} " +
            "packets").format(
                float(self.packets) / num_packets * 100, self.packets,
                num_packets, self.network.cycle, len(self.network.packets)),
              file=sys.stderr, end="")

    def subclasses(self, cls):
        """
            I started to need recursive subclass discovery, so ack to
            http://stackoverflow.com/a/17246726/5102124
        """
        classes = []
        for sc in cls.__subclasses__():
            classes.append(sc)
            classes.extend(self.subclasses(sc))
        return classes

    def sim(self):
        classes = {x.__name__[7:]: x for x in self.subclasses(netsim_basenet)}
        if (self.kwargs['network_type'] == 'help' or
                self.kwargs['network_type'] not in classes.keys()):
            print('Available networks: {}'.format(
                ', '.join(sorted(classes.keys()))))
            sys.exit(0)
        self.network = classes[self.kwargs['network_type']](
            self.kwargs['network_opts'], self.ntrc.hdr.num_nodes)
        tf = self.kwargs['<trace>'] + ".map"
        print("Loading map", file=sys.stderr)
        mapping = self.gather_nodes(tf)
        print("Mapping nodes", file=sys.stderr)
        self.network.map_nodes(mapping)
        if self.kwargs['region'] != 'all':
            self.kwargs['region'] = int(self.kwargs['region'])
            self.limit = 1
            print("Seeking in compressed file", file=sys.stderr)
        else:
            self.kwargs['region'] = 0
            self.limit = None
        self.ntrc.seek(self.kwargs['region'], self.limit)
        print("Start simulation", file=sys.stderr)
        then = time.time() * 1000
        last_pkt = None
        pkt = self.ntrc.read_packet()
        if pkt and self.kwargs['region']:
            ffwd = pkt.data.cycle
            print("Fast forward simulation to cycle {}".format(ffwd))
            self.network.cycle = ffwd
        while True:
            if self.kwargs['progress']:
                now = time.time() * 1000
                if now - then > 100:
                    self.progress()
                    then = now
            if not pkt or (
                    self.kwargs['packet_limit'] and
                    self.packets >= int(self.kwargs['packet_limit'])):
                if self.kwargs['progress']:
                    self.progress()
                    print(file=sys.stderr)
                self.drain()
                if self.packets:
                    print("End cycle: {}, originally: {}".format(
                        self.network.cycle-1, last_pkt.data.cycle))
                break
            self.packets += 1
            # Simulate at least as far as this packet's original inject cycle
            self.step(pkt.data.cycle)
            self.network.register(pkt)
            last_pkt = pkt
            pkt = self.ntrc.read_packet()

    def __init__(self, nt, **kwargs):
        self.ntrc = nt
        self.kwargs = kwargs
        self.packets = 0


if __name__ == "__main__":
    ARGS = docopt('\n'.join(__doc__.split('\n')[:-24]), version='1.0')
    ns = netsim(netrace(ARGS['<trace>']),
                **{k.strip('--').replace('-', '_'):
                v for k, v in ARGS.items()})
    if ARGS['map']:
        ns.map()
    else:
        ns.sim()
