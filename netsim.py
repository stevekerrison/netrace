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
        self.active = []
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
        self.chain = [src]

    def open(self, node):
        """
            Add path along the route
        """
        if node in self.nodes:
            raise KeyError("Node already registered for this packet")
        self.nodes[node] = 0
        self.chain.append(node)

    def propagate(self):
        """
            Move data along route, throttled by nodes. Returns nodes that have
            sent all data so the network simulator can purge queues.
        """
        if len(self.chain) == 1:
            if self.chain[0] == self.dst:
                # Rate limit, or transfer all available data if no rate set
                rate = min(self.dst.rate, self.nodes[self.dst])
                self.nodes[self.dst] -= rate
            else:
                # Viable route not open yet, no data can move
                pass
        elif len(self.chain) > 1:
            for (s, d) in zip(
                    reversed(self.chain[:-1]), reversed(self.chain[1:])):
                # Rate limit, or transfer all available data if no rate set
                rate = min(s.rate, self.nodes[s])
                self.nodes[s] -= rate
                self.nodes[d] += rate
        closed = []
        # Close tail as far as the next waiting data
        while len(self.chain) and not self.nodes[self.chain[0]]:
            closed.append((self.chain[0], self.pkt))
            del self.nodes[self.chain[0]]
            del self.chain[0]
        return closed

    def __len__(self):
        """Return the number of bytes still in transit"""
        return sum(self.nodes.values())


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
        if ( self.cycle in self.dispatchable and pkt.data.id in
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
            # Move all data to receiver straight away
            self.routes[pkt].propagate()

    def update_delaycache(self, pktid, delay):
        was = None if pktid not in self.delaycache else self.delaycache[pktid]
        if was is None or delay > was:
            self.delaycache[pktid] =  delay

    def inject(self, pkt):
        """Start routing packet"""
        pkt.cycle_adj = self.cycle - pkt.data.cycle
        # Zero network opens route to destination instantly
        self.route(pkt, self.bynid[netsim_node.dst_from_packet(pkt)])

    def clear(self, closures):
        for node, pkt in closures:
            if pkt not in node.active:
                raise RuntimeError(
                    "Packet {} was expected to be active on node {}".format(
                        pkt.data.id, node))
            node.active.remove(pkt)
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
                pkt = n.active[0]
                closures += self.routes[pkt].propagate()
            elif len(n.q['recv']):
                # We're not active but can be
                pkt = n.q['recv'].pop()
                n.active.append(pkt)
                closures += self.routes[pkt].propagate()
        self.clear(closures)
        if self.cycle in self.dispatchable:
            for pktid in self.dispatchable[self.cycle]:
                self.inject(self.packets[pktid])
            del self.dispatchable[self.cycle]



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
        assert(2**self.bits < self.channels)
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
            -d dirs --directions=dirs   Number of directions per switch
                                        [default: 2]
            -b bits --buffering=bits    Amount of buffering per port
                                        [default: 128]
    """
    def __init__(self, argstr, num_nodes):
        super().__init__(argstr, num_nodes)
        self.xy = int(math.sqrt(self.num_nodes))
        assert(self.xy == math.sqrt(self.num_nodes))
        self.buffering = int(self.ARGS['--buffering'])
        self.directions = int(self.ARGS['--directions'])

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
        for nodeid in l1:
            # TODO: of l1i == l1i == l2?
            nid = ('l1d', nodeid)
            self.add_node(netsim_node(nid, (x, y)))
            nid = ('l1i', nodeid)
            self.add_node(netsim_node(nid, (x + 1, y)))
            nid = ('l2', nodeid)
            self.add_node(netsim_node(nid, (x + 2, y)))
            x = x + 3 if x + 3 < self.xy * 3 else 0
            y = y if x else y + 1
            if x / 3 == self.xy / 2:
                # Skip a row in the middle for mem controllers
                x += 1
        y = 0
        x = 3 * (self.xy // 2)
        for nodeid in mc:
            # MCs straight down the middle
            nid = ('mc', nodeid)
            self.add_node(netsim_node(nid, (x, y)))
            y += 1


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
                float(self.packets) /num_packets * 100, self.packets,
                num_packets, self.network.cycle, len(self.network.packets)),
              file=sys.stderr, end="")

    def sim(self):
        classes = {x.__name__[7:]: x for x in netsim_basenet.__subclasses__()}
        if (self.kwargs['network_type'] == 'help' or
                self.kwargs['network_type'] not in classes.keys()):
            print('Available networks: {}'.format(', '.join(classes.keys())))
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
                    print(self.network.cycle-1, last_pkt.data.cycle)
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
