# coding:utf-8
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

from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches

import networkx as nx
import copy


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Initialize the Graph representing our test-topology."""
        super(ProjectController, self).__init__(*args, **kwargs)
        self.hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.slices = dict()
        self.slices[5004] = set()
        self.slices[10022] = set()
        self.slices[10023] = set() # elemts will be tuples (ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, path, of_priority)
        self.datapaths = []
        self.slice_ports = [5004, 10022, 10023] # video, latency, mission critical voip
        self.slice_protocols = [17, 6] # UDP and TCP
        # set all to 0 for no slicing (only default queue is used)
        self.DEFAULT_QUEUE = 0
        # the video queue can either be the same as default to use it as noise
        # or we use queue_id=1 to show that different video traffic can be
        # prioritized and have a min-rate or something
        self.VIDEO_QUEUE = 0
        self.LATENCY_QUEUE = 2
        self.CRITICAL_QUEUE = 3

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
        """Add table-miss flow entry."""
        self.logger.info("\n-----------switch_features_handler is called")

        msg = ev.msg
        # self.logger.info('OFPSwitchFeatures received: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (
        #     msg.datapath_id, msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities))
        self.logger.info("Setting table-miss flow entry.")
        datapath = ev.msg.datapath
        self.datapaths.append(datapath)
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("switch_features_handler is over\n")

    def add_port_based_flow(self, datapath, dst_port, ipv4_src, ipv4_dst, actions, priority, protocol):
        """Add flow with matching protocol (UDP=17/TCP=6), dst_port, ipv4-src and ipv4-dst."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if protocol == 17:
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)

            self.logger.info("\nAdding UDP flow: switch {}\nmatch:{}\nactions={}\n".format(datapath.id, match, actions))
        elif protocol == 6:
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
            self.logger.info("\nAdding TCP flow: switch {}\nmatch:{}\nactions={}\n".format(datapath.id, match, actions))

        else:
            self.logger.info("ERROR: Protocol {} not supported!".format(protocol))
            return
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority, instructions=inst)
        datapath.send_msg(mod)

    def add_slice(self, datapath, ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, of_priority):
        """Calculate the shortest path based on 'weight', then add the
        necessary flow-entry with the correct out_port and the correct
        'queue_id' for this slice."""
        dpid = datapath.id
        try:
            path = nx.shortest_path(self.net, dpid, ipv4_dst, weight=weight)
        except Exception:
            self.logger.info("ERROR add_slice: {} to {} no shortest_path".format(dpid, ipv4_dst))
            return (None, self.DEFAULT_QUEUE)
        if dpid in path:
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
            actions = [
                datapath.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
                datapath.ofproto_parser.OFPActionOutput(out_port)]

            self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                     ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                     actions=actions, priority=of_priority,
                                     protocol=protocol)
            if dst_port == 5004:
                # increase video weight!
                # possible problem: handler is called multiple times because of
                # high packet rate -> different paths are chosen every time
                # because weight was increased
                pass
            try:
                path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight=weight)
            except Exception:
                self.logger.info("ERROR add_slice2: {} to {} no shortest_path".format(ipv4_src, ipv4_dst))
                return (None, self.DEFAULT_QUEUE)
            if dpid in path:
                self.logger.info("\n\nADDING:\n{}\n".format((ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, tuple(path), of_priority)))
                try:
                    self.slices[dst_port].add((ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, tuple(path), of_priority))
                except KeyError:
                    self.logger.info("{} not in self.slices!".format(dst_port))
            return (out_port, queue_id)
        else:
            self.logger.info("ERROR: Switch {} called add_slice but packet is not on shortest path!".format(dpid))
            return (None, self.DEFAULT_QUEUE)

    def add_base_flow(self, datapath, ipv4_src, ipv4_dst):
        """Used for non-special traffic, adds a flow based on 'weight'
        and also flows with higher priority to make sure that UDP/TCP packets
        with special ports are send to the controller again for custom
        flow processing (adding the correct slice)."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        try:
            path = nx.shortest_path(self.net, dpid, ipv4_dst, weight="weight")
        except Exception:
            self.logger.info("ERROR add_base_flow: {} to {} no shortest_path".format(dpid, ipv4_dst))
            return (None, self.DEFAULT_QUEUE)

        if dpid in path:
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
            actions = [
                datapath.ofproto_parser.OFPActionSetQueue(queue_id=self.DEFAULT_QUEUE),
                datapath.ofproto_parser.OFPActionOutput(out_port)]
        else:
            self.logger.info("ERROR: Switch {} got a packet but is not in the shortest path!".format(dpid))
            return (None, self.DEFAULT_QUEUE)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("SWITCH {} : Adding base rule for src:{} dst:{}".format(dpid, ipv4_src, ipv4_dst))

        # add additional flows to make sure the switch asks the controller again
        # for special packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("Adding callback rules for higher slice packets.")
        for protocol in self.slice_protocols:
            for dst_port in self.slice_ports:
                self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                         ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                         actions=actions, priority=2,
                                         protocol=protocol)
        self.logger.info("---------------------\n")
        return (out_port, self.DEFAULT_QUEUE)

    def fail_node(self, failed_node):
        """Removes node from network, deletes all flows from every switch
        and adds table-miss flow again."""
        if failed_node in self.net:
            self.logger.info("Removing node {} from self.net".format(failed_node))
            self.net.remove_node(failed_node)
        else:
            self.logger.info("Node {} was already removed... dropping!".format(failed_node))
            return
        for datapath in self.datapaths:
            self.remove_flows(datapath)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0, instructions=inst)
            datapath.send_msg(mod)

    def remove_flows(self, datapath):
        """Create OFP flow mod message to remove all flows from a switch."""
        self.logger.info("REMOVING ALL FLOWS FOR SWITCH:{} !!".format(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        instructions = []
        mod = parser.OFPFlowMod(
            datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=1, buffer_id=ofproto.OFPCML_NO_BUFFER,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, flags=0,
            match=match, instructions=instructions)
        datapath.send_msg(mod)

    def repolpulate_switches(self, failed_node):
        iter_dict = copy.deepcopy(self.slices)
        for port, sl_set in iter_dict.iteritems():
            tmp = set(sl_set)
            for sl in sl_set:
                if (failed_node == sl[6][1]) or (failed_node == sl[6][-2]):
                    self.logger.info("Removing {}".format(sl))
                    tmp.remove(sl)
            self.slices[port] = tmp
        port = 10023
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            if failed_node in sl[6]:
                self.logger.info("\nRemove was called for slice:\n{}".format(sl))
                tmp.remove(sl)
            self.logger.info("\nRecalculate was called for slice:\n{}".format(sl))
            tmp.add(self.recalc_slice(sl))
        self.slices[port] = tmp
        port = 10022
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            if failed_node in sl[6]:
                self.logger.info("\nRemove was called for slice:\n{}".format(sl))
                tmp.remove(sl)
            self.logger.info("\nRecalculate was called for slice:\n{}".format(sl))
            tmp.add(self.recalc_slice(sl))
        self.slices[port] = tmp

        port = 5004
        tmp = set(self.slices[port])
        for sl in self.slices[port]:
            self.logger.info("-------")
            if failed_node in sl[6]:
                self.logger.info("\nRemove was called for slice:\n{}".format(sl))
                tmp.remove(sl)
            self.logger.info("\nRecalculate was called for slice:\n{}".format(sl))
            tmp.add(self.recalc_slice(sl))
        self.slices[port] = tmp

    def recalc_slice(self, sl):
        ipv4_src, ipv4_dst, protocol, dst_port, queue_id, weight, path, of_priority = sl
        try:
            path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight=weight)
        except Exception:
            self.logger.info("ERROR recalc_slice: {} to {} no shortest_path".format(ipv4_src, ipv4_dst))
            return
        for datapath in self.datapaths:
            dpid = datapath.id
            if dpid in path:
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

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_handle = pkt.get_protocol(ipv4.ipv4)
        dpid = datapath.id
        out_port = None
        queue_id = self.DEFAULT_QUEUE

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
        if dst == '10.0.0.11':
            # simulate switch failure s1
            self.fail_node(1)
            self.repolpulate_switches(1)
            return
        elif dst == '10.0.0.22':
            # simulate switch failure s2
            self.fail_node(2)
            self.repolpulate_switches(2)
            return
        elif dst == '10.0.0.33':
            # simulate switch failure s3
            self.fail_node(3)
            self.repolpulate_switches(3)
            return
        elif dst == '10.0.0.44':
            # simulate switch failure s4
            self.fail_node(4)
            self.repolpulate_switches(4)
            return
        else:
            # possibly do link failure as well
            pass

        try:
            dst_port = pkt.protocols[2].dst_port
        except Exception:
            self.logger.info("NON SLICE PROTOCOL: {}".format(protocol))

        # shouldn't be necessary but in case a new host is added we can add it
        # to the graph with this
        if src not in self.net:
            self.logger.info("ERROR: adding {} to graph".format(src))
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0, video=0, latency=0, mission_critical=0)
            self.net.add_edge(src, dpid, weight=0, video=0, latency=0, mission_critical=0)

        if protocol in self.slice_protocols and dst_port in self.slice_ports:
            if dst_port == 5004:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.VIDEO_QUEUE))
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='video',
                                                    queue_id=self.VIDEO_QUEUE,
                                                    protocol=protocol, of_priority=3)
            elif dst_port == 10022:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.LATENCY_QUEUE))
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='latency',
                                                    queue_id=self.LATENCY_QUEUE,
                                                    protocol=protocol, of_priority=3)
              # chao'work
            elif dst_port == 10023:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.CRITICAL_QUEUE))
                out_port, queue_id = self.add_slice(datapath=datapath, ipv4_src=src,
                                                    ipv4_dst=dst, dst_port=dst_port,
                                                    weight='mission_critical',
                                                    queue_id=self.CRITICAL_QUEUE,
                                                    protocol=protocol, of_priority=3)
            # add broadcast use switch with in_port==2 to set TTL
            # add multicast (not sure how yet)

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

        actions = [datapath.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
                   datapath.ofproto_parser.OFPActionOutput(out_port)]
        #actions = [datapath.ofproto_parser.OFPActionSetQueue(queue_id=self.DEFAULT_QUEUE),
        #           datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)
