#!/usr/bin/env python
# coding:utf-8

# The following License is from an example switch implentation that Chao found,
# We only use the main idea of having a graph representation of the network and
# the mechanism to figure out the next out_port as marked in the code. Some other
# parts like the table-miss entry are standards that are found in any ryu app

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import arp

from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches

import networkx as nx
import copy
import time
#multicast
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import *
import sys
import ilib



ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__





class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'igmplib': ilib.IgmpLib}

    def __init__(self, *args, **kwargs):
        """Initialize the Graph representing our test-topology."""
        super(ProjectController, self).__init__(*args, **kwargs)

        ############################################
        # Switch on smart features like slicing using QoS queues and automatic
        # rerouting after switch failure
        self.smart = True
        # otherwise all slices use same queue and switch failure is like network-reset
        ############################################

        self.hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        # self.slices is a dictionary that will hold all existing slice flows,
        # keys are the destination-ports, values are sets of slices as seen below
        self.slices = dict()
        # elements  of these sets will be slice-flows represented as
        # tuples: (ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, path, of_priority)
        self.slices[5004] = set()
        self.slices[10022] = set()
        self.slices[10023] = set()
        # save datapaths of all switches to be able to send them FlowMods
        self.datapaths = []
        # define what protocols are supported: UDP=17 and TCP=6
        # numbers are those used for 'ip_proto' field in parser.OFPMatch
        self.slice_protocols = [17, 6]
        self.DEFAULT_QUEUE = 0
        self.VIDEO_QUEUE = 0 # is set to 0 to use it as base-line-noise
        self.MULTICAST_QUEUE = 0
        self.LATENCY_QUEUE = 0
        self.CRITICAL_QUEUE = 0
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

        if self.smart:
            self.MULTICAST_QUEUE = 1
            self.LATENCY_QUEUE = 2
            self.CRITICAL_QUEUE = 3

        # the idea to use networkx.DiGraph is from Chao's book
        self.net = nx.DiGraph()
        for i in range(4):
            self.net.add_node(self.hosts[i])
            self.net.add_edge(i+1, self.hosts[i], port=2, weight=0, video=0, latency=0, mission_critical=0)
            self.net.add_edge(self.hosts[i], i+1, weight=0, video=0, latency=0, mission_critical=0)

        self.net.add_node(1)
        self.net.add_node(2)
        self.net.add_node(3)
        self.net.add_node(4)
        # set different weights for static slicing based on link properties
        # the idea to save the port in the edge as seen below is from Chao's book
        self.net.add_edge(1, 2, port=3, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(2, 1, port=4, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(2, 3, port=3, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(3, 2, port=4, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(3, 4, port=3, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(4, 3, port=4, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(4, 1, port=3, weight=1, video=1, latency=1, mission_critical=1)
        self.net.add_edge(1, 4, port=4, weight=1, video=1, latency=1, mission_critical=1)
        self.logger.info("**********ProjectController __init__")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Add table-miss flow entry and add the switches datapath to
        self.datapaths for future Flow Modification."""
        self.logger.info("\n-----------switch_features_handler is called")

        msg = ev.msg
        self.logger.info("Setting table-miss flow entry.")
        datapath = ev.msg.datapath
        self.datapaths.append(datapath)
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # empty match means that every packet that comes in matches this rule
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=5, hard_timeout=15, priority=priority,match=match instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("switch_features_handler is over\n")

    def add_port_based_flow(self, datapath, dst_port, ipv4_src, ipv4_dst, actions, priority, protocol):
        """Add flow with matching protocol (UDP=17/TCP=6), dst_port, ipv4-src and ipv4-dst."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if protocol == 17:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
            self.logger.info("\nAdding UDP flow: switch {}\nmatch:{}\nactions={}\n".format(datapath.id, match, actions))
        elif protocol == 6:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
            self.logger.info("\nAdding TCP flow: switch {}\nmatch:{}\nactions={}\n".format(datapath.id, match, actions))
        else:
            self.logger.info("ERROR: Protocol {} not supported!".format(protocol))
            return
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority, instructions=inst)
        datapath.send_msg(mod)

    def add_slice(self, datapath, ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, of_priority):
        """Calculate the shortest path based on custom weight, then add the
        necessary flow-entry with the correct out_port and the correct
        'queue_id' for this slice."""
        dpid = datapath.id
        try:
            # calculate path from switch to destination
            path = nx.shortest_path(self.net, dpid, ipv4_dst, weight=weight)
        except Exception:
            self.logger.info("ERROR add_slice: {} to {} no shortest_path".format(dpid, ipv4_dst))
            return (None, self.DEFAULT_QUEUE)
        next = path[path.index(dpid) + 1]           # this and all reoccurences
        out_port = self.net[dpid][next]['port']     # are from Chao's book
        actions = [
            datapath.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
            datapath.ofproto_parser.OFPActionOutput(out_port)]

        try:
            # calculate path from src to destination
            src_path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight=weight)
            sl = (ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, tuple(src_path), of_priority)
            if sl not in self.slices[dst_port]:
                self.logger.info("\nADDING NEW SLICE-FLOW: ipv4_src={}, ipv4_dst={}, protocol={}, dst_port={},\nqueue_id={}, weight={}\ntuple(path)={}, of_priority={}\n".format(*sl))
                self.slices[dst_port].add(sl)
            else:
                self.logger.info("Slice-flow {} already initialized, just adding rule to switch {}".format(sl, dpid))
        except KeyError:
            self.logger.info("ERROR {} not in self.slices!".format(dst_port))
        except Exception:
            self.logger.info("ERROR add_slice2: {} to {} no shortest_path".format(ipv4_src, ipv4_dst))
            return (None, self.DEFAULT_QUEUE)

        self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                 ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                 actions=actions, priority=of_priority,
                                 protocol=protocol)
        return (out_port, queue_id)

    def add_base_flow(self, datapath, ipv4_src, ipv4_dst):
        """Used for non-special traffic, adds a flow based on 'weight'
        and also flows with higher priority to make sure that UDP/TCP packets
        with special ports are send to the controller again for custom
        flow processing (adding the correct slice)."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        try:
            path = nx.shortest_path(self.net, dpid, ipv4_dst, weight="weight")
        except Exception:
            self.logger.info("ERROR add_base_flow: {} to {} no shortest_path".format(dpid, ipv4_dst))
            return (None, self.DEFAULT_QUEUE)

        next = path[path.index(dpid) + 1]
        out_port = self.net[dpid][next]['port']

        actions = [
            parser.OFPActionSetQueue(queue_id=self.DEFAULT_QUEUE),
            parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1, instructions=inst)
        self.logger.info("SWITCH {} : Adding base rule for src:{} dst:{}".format(dpid, ipv4_src, ipv4_dst))
        datapath.send_msg(mod)

        # add additional flows to make sure the switch asks the controller again
        # how to process special-packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.logger.info("Adding callback rules for higher slice packets.")
        for protocol in self.slice_protocols:
            for dst_port in self.slices:
                self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                         ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                         actions=actions, priority=2,
                                         protocol=protocol)
        self.logger.info("---------------------\n")
        return (out_port, self.DEFAULT_QUEUE)

    def fail_node(self, failed_node):
        """Removes node from network, deletes all flows from every switch
        and adds table-miss flow again. After this it is as if the network
        had been reset without the failed switch."""
        if failed_node in self.net:
            self.logger.info("Removing node {} from self.net".format(failed_node))
            self.net.remove_node(failed_node)
        else:
            self.logger.info("Node {} was already removed... dropping!".format(failed_node))
            return
        for datapath in self.datapaths:
            # remove all flow-entries from this switch
            self.remove_flows(datapath)
            # set table miss again
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0, instructions=inst)
            datapath.send_msg(mod)

    def remove_flows(self, datapath):
        """Send OFP flow mod message to remove all flows from a switch."""
        self.logger.info("REMOVING ALL FLOWS FOR SWITCH:{} !!".format(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        instructions = []
        mod = parser.OFPFlowMod(
            datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=1, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, flags=0,
            match=match, instructions=instructions)
        datapath.send_msg(mod)

    def repopulate_switches(self, failed_node):
        """Send all necessary rules to all switches to reestablish existing
        flows with new routes. Impossible flows will be removed."""
        # copy dictionary for save iteration
        iter_dict = copy.deepcopy(self.slices)
        # remove all slices with src or dst node unreachable from the self.slices dict
        for port, sl_set in iter_dict.iteritems():
            tmp = set(sl_set)
            for sl in sl_set:
                path = sl[6]
                # the following check is based on the assumption that if e.g.
                # switch 3 has failed the corresponding host h3 is unreachable.
                # to check this the path saved in sl[6] is used: a path looks
                # like this: (10.0.0.1, 1, 4, 3, 10.0.0.3)
                # so if the second element of the path is the failed node it is
                # impossible to reroute, same if the second to last element in
                # the path is the failed node
                if (failed_node == path[1]) or (failed_node == path[-2]):
                    self.logger.info("Permanently removing {} because host h{} became unreachable!".format(sl, failed_node))
                    tmp.remove(sl)
            self.slices[port] = tmp

        # reestablish existing slices based on new topology
        # do it in the order of priority 10023, 10022, 5004
        port = 10023
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            path = sl[6]
            if failed_node in path:
                self.logger.info("\nRerouting:\n{}".format(sl))
                tmp.remove(sl)
            new_slice = self.reestablish_slice(sl)
            if new_slice not in tmp:
                tmp.add(new_slice)
        self.slices[port] = tmp

        port = 10022
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            path = sl[6]
            if failed_node in path:
                self.logger.info("\nRerouting:\n{}".format(sl))
                tmp.remove(sl)
            new_slice = self.reestablish_slice(sl)
            if new_slice not in tmp:
                tmp.add(new_slice)
        self.slices[port] = tmp

        port = 5004
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            path = sl[6]
            if failed_node in path:
                self.logger.info("\nRerouting:\n{}".format(sl))
                tmp.remove(sl)
            new_slice = self.reestablish_slice(sl)
            if new_slice not in tmp:
                tmp.add(new_slice)
        self.slices[port] = tmp

    def reestablish_slice(self, sl):
        """Reestablish an existing slice(-flow) by recalculating the shortest
        path and sending all necessary rules to the switches along the path."""
        ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, path, of_priority = sl
        try:
            path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight=weight)
        except Exception:
            self.logger.info("ERROR reestablish_slice: {} to {} no shortest_path".format(ipv4_src, ipv4_dst))
            return
        for datapath in self.datapaths:
            dpid = datapath.id
            if dpid in path:
                # switch is in the path so send him the right out_port and queue
                next = path[path.index(dpid) + 1]
                out_port = self.net[dpid][next]['port']
                actions = [
                    datapath.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
                    datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                         ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                         actions=actions, priority=of_priority,
                                         protocol=protocol)
        return (ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, tuple(path), of_priority)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """packet_in_handler is called whenever a flow does not have a matching
        flow_entry. If the packet is a UDP/TCP packet with one of the
        slice_ports as destination port, then the flow entries to create the
        corresponding network-slice are send to the switch. If it is a
        non-special packet (non of the slice_ports), a 'base_flow' is added to
        ensure connectivity but it only uses the default-queue and no special
        route. For simplicity we only support IPv4-packets, all others are
        dropped."""
        msg = ev.msg
        datapath = msg.datapath
        self.logger.info("**********_packet_in_handler\nSWITCH {}\n".format(datapath.id))
        t1 = time.clock()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)[0]
        ipv4_handle = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id
        out_port = None
        queue_id = self.DEFAULT_QUEUE
#chao's work about broadcast begin
        header_list = dict(
            (p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning

        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                # 1:reply or drop;  0: flood
                print "ARP_PROXY_13"
                return None
            else:
                out_port = ofproto.OFPP_FLOOD
                print 'OFPP_FLOOD'

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
#chao's work about broadcast end
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        try:
            dst = ipv4_handle.dst
            src = ipv4_handle.src
            protocol = ipv4_handle.proto
        except Exception:
            self.logger.error("ERROR:\n{} is not an IPv4-Packet! Dropping..\n".format(pkt))
            return

        # use certain destination IPs to 'detect'/simulate switch failure
        # so in the demo we do: 'switch s3 stop' and 'h1 ping -c1 10.0.0.33'
        # now both mininet and the controller know that s3 has failed
        if dst == '10.0.0.11':
            # simulate switch failure s1
            sw = 1
            self.logger.info("---------FAILURE HANDLING switch {}---------".format(sw))
            self.fail_node(sw)
            if self.smart:
                self.repopulate_switches(sw)
            self.logger.info("---------FAILURE HANDLING OVER---------")
            return
        elif dst == '10.0.0.22':
            # simulate switch failure s2
            sw = 2
            self.logger.info("---------FAILURE HANDLING switch {}---------".format(sw))
            self.fail_node(sw)
            if self.smart:
                self.repopulate_switches(sw)
            self.logger.info("---------FAILURE HANDLING OVER---------")
            return
        elif dst == '10.0.0.33':
            # simulate switch failure s3
            sw = 3
            self.logger.info("---------FAILURE HANDLING switch {}---------".format(sw))
            self.fail_node(sw)
            if self.smart:
                self.repopulate_switches(sw)
            self.logger.info("---------FAILURE HANDLING OVER---------")
            return
        elif dst == '10.0.0.44':
            # simulate switch failure s4
            sw = 4
            self.logger.info("---------FAILURE HANDLING switch {}---------".format(sw))
            self.fail_node(sw)
            if self.smart:
                self.repopulate_switches(sw)
            self.logger.info("---------FAILURE HANDLING OVER---------")
            return
        else:
            # possibly do link failure as well
            pass

        try:
            dst_port = pkt.protocols[2].dst_port
        except Exception:
            self.logger.info("NO Destination Port in protocol: {}".format(protocol))

        # shouldn't be necessary but in case a new host is added we can add it
        # to the graph with this
        if src not in self.net:
            self.logger.info("ERROR: adding {} to graph".format(src))
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0, video=0, latency=0, mission_critical=0)
            self.net.add_edge(src, dpid, weight=0, video=0, latency=0, mission_critical=0)

        if protocol in self.slice_protocols and dst_port in self.slices:
            if dst_port == 5004:
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='video',
                                                    queue_id=self.VIDEO_QUEUE,
                                                    protocol=protocol, of_priority=3)
            elif dst_port == 10022:
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='latency',
                                                    queue_id=self.LATENCY_QUEUE,
                                                    protocol=protocol, of_priority=3)
              # chao's work
            elif dst_port == 10023:
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='mission_critical',
                                                    queue_id=self.CRITICAL_QUEUE,
                                                    protocol=protocol, of_priority=3)
            # add broadcast on port 10000: idea: use switch with in_port==2 to set TTL=3,

            # because this is always the entry to the loop
            # so something like 'if in_port==2: self.set_TTL_and_flood()' should do the trick
        elif protocol in self.slice_protocols and dst_port in range(11000, 11444):
            # add multicast:
            # assume that you have a src and a list of destinations like so:
            # check for last three digits in port and use them as destinations:
            # so when h1 wants to multicast to h2 and h3 it will use UDP-Port 11023
            dst = None # destinations are implied by dst_port
            dst_list = []
            for digit in str(dst_port)[2:]:
                tmp_dst = "10.0.0.{}".format(digit)
                if tmp_dst in self.hosts and tmp_dst not in dst_list:
                        dst_list.append(tmp_dst)
            self.logger.info("GOT MULTICAST with src:{} and dst_list={}".format(src, dst_list))
            # now you have a list of destinations and can figure out how to send them
            # the data (they listen on UDP-port 10001) assume that traffic is only in one direction
            # and for simplicity there is only one multicast going on in the network and only UDP:
            #
            # implement  something like self.add_multicast_flows(src, dst_list)
            #
            # these are only suggestions:
            # calculate paths from src to all destinations and check for overlap.
            # in the overlapping part use one single flow and in the last overlapping
            # switch split the packet and set the correct dst-IP to send to every destination from here on separately
            # e.g. h1 wants to send to h2 and h3:
            # send on this path: (10.0.0.1, 1, 2) then in switch 2 the packet is split,
            # one is send to 10.0.0.2 the other to switch 3 and then 10.0.0.3
            #
            # keep in mind that for some destinations there are multiple shortest_paths
            # so maybe use nx.all_shortest_paths and then figure out which one's overlap the most

        else:
            # non-special traffic!
            if dst in self.net and out_port is None:
                out_port, queue_id = self.add_base_flow(datapath=datapath,
                                                        ipv4_src=src,
                                                        ipv4_dst=dst)
            else:
                self.logger.info("{} not known to controller, dropping ..".format(dst))
                return
        if out_port is None:
            self.logger.info("\nERROR: NO FLOWS ADDED!!! SWITCH {} : pkt: \n{}\n\nDROPPING..!".format(dpid, pkt))
            return

        actions = [parser.OFPActionSetQueue(queue_id=queue_id),
                   parser.OFPActionOutput(out_port)]

        # make sure data is not lost if packet is not buffered at switch!
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        # self.logger.info("out={}".format(out))
        self.logger.info("TIME elapsed in controller: {}s".format(time.clock() - t1))
        self.logger.info("___________________________packet_in is over\n")
#chao"2th work about broadcast
 def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            hwtype = header_list[ARP].hwtype
            proto = header_list[ARP].proto
            hlen = header_list[ARP].hlen
            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(
                        in_port)
                    )

                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False


@set_ev_cls(ilib.EventMulticastGroupStateChanged, MAIN_DISPATCHER)
def _status_changed(self, ev):
    msg = {

        ilib.MG_GROUP_ADDED: 'Multicast Group Added',

        ilib.MG_MEMBER_CHANGED: 'Multicast Group Member Changed',

        ilib.MG_GROUP_REMOVED: 'Multicast Group Removed',

    }

    self.logger.info("%s: [%s] querier:[%s] hosts:%s", msg.get(ev.reason), ev.address, ev.src, ev.dsts)