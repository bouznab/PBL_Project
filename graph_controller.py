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


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Initialize the Graph representing our test-topology."""
        super(ProjectController, self).__init__(*args, **kwargs)
        self.hosts = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.slice_ports = [5004, 10022] # video and latency TODO third slice
        self.slice_protocols = [17, 6] # UDP and TCP
        self.VIDEO_QUEUE = 0
        self.LATENCY_QUEUE = 1
        self.AUDIO_QUEUE = 2

        self.net = nx.DiGraph()
        for i in range(4):
            self.net.add_node(self.hosts[i])
            self.net.add_edge(i+1, self.hosts[i], port=2, weight=0, video=0, latency=0)
            self.net.add_edge(self.hosts[i], i+1, weight=0, video=0, latency=0)

        self.net.add_node(1)
        self.net.add_node(2)
        self.net.add_node(3)
        self.net.add_node(4)
        self.net.add_edge(1, 2, port=3, weight=2, video=2, latency=2)
        self.net.add_edge(2, 1, port=4, weight=1, video=1, latency=1)
        self.net.add_edge(2, 3, port=3, weight=1, video=1, latency=1)
        self.net.add_edge(3, 2, port=4, weight=1, video=1, latency=1)
        self.net.add_edge(3, 4, port=3, weight=1, video=1, latency=1)
        self.net.add_edge(4, 3, port=4, weight=1, video=1, latency=1)
        self.net.add_edge(4, 1, port=3, weight=1, video=1, latency=1)
        self.net.add_edge(1, 4, port=4, weight=1, video=1, latency=1)
        self.logger.info("**********ProjectController __init__")

    # Handy function that lists all attributes in the given object
    # def ls(self, obj):
    #     self.logger.info("\n".join([x for x in dir(obj) if x[0] != "_"]))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Add table-miss flow entry."""
        self.logger.info("\n-----------switch_features_handler is called")

        msg = ev.msg
        # self.logger.info('OFPSwitchFeatures received: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (
        #     msg.datapath_id, msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities))
        self.logger.info("Setting table-miss flow entry.")
        datapath = ev.msg.datapath
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
        """Add flow with matching dst_port, ipv4-src and ipv4-dst."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if protocol == 17:
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, udp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)

            self.logger.info("\nAdding UDP flow:\nmatch:{}\nactions={}\n".format(match, actions))
        elif protocol == 6:
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ip_proto=protocol, tcp_dst=dst_port,
                ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)

            self.logger.info("\nAdding TCP flow:\nmatch:{}\nactions={}\n".format(match, actions))
        else:
            self.logger.info("ERROR: Protocol {} not supported!".format(protocol))
            return
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=priority, instructions=inst)
        datapath.send_msg(mod)

    def add_slice(self, datapath, ipv4_src, ipv4_dst, dst_port, weight, queue_id, protocol, of_priority):
        dpid = datapath.id
        path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight=weight)
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
            return out_port
        else:
            self.logger.info("ERROR: Switch {} called add_slice but packet is not on shortest path!".format(dpid))
            return None

    def add_base_flow(self, datapath, ipv4_src, ipv4_dst):
        """Used for non-special traffic, adds a flow based on weight_latency
        and also flows with higher priority to make sure that UDP packets
        with special ports are send to the controller again for custom
        flow processing."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        path = nx.shortest_path(self.net, ipv4_src, ipv4_dst, weight="weight")
        if dpid in path:
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
            actions = [
                datapath.ofproto_parser.OFPActionSetQueue(queue_id=0),
                datapath.ofproto_parser.OFPActionOutput(out_port)]
        else:
            self.logger.info("ERROR: Switch {} got a packet but is not in the shortest path!".format(dpid))
            return None

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("SWITCH {} : Adding base rule for src:{} dst:{}".format(dpid, ipv4_src, ipv4_dst))

        # add additional flows to make sure the switch asks the controller again
        # for important packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.logger.info("Adding callback rules for higher slice packets.")
        for protocol in self.slice_protocols:
            for dst_port in self.slice_ports:
                self.add_port_based_flow(datapath=datapath, dst_port=dst_port,
                                         ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,
                                         actions=actions, priority=2,
                                         protocol=protocol)
        self.logger.info("---------------------\n")
        return out_port

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Packets with UDP-dst-port 5004 and 10022 have special flows added
        to the switch all others are asigned to the 'base-slice' witch arbitrary
        routing."""
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
        try:
            dst_port = pkt.protocols[2].dst_port
        except Exception:
            self.logger.info("NON SLICE PROTOCOL: {}".format(protocol))

        # shouldn't be necessary but in case a new host is added we can add it
        # to the graph with this
        if src not in self.net:
            self.logger.info("ERROR: adding {} to graph".format(src))
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0, video=0, latency=0)
            self.net.add_edge(src, dpid, weight=0, video=0, latency=0)

        if protocol in self.slice_protocols and dst_port in self.slice_ports:
            if dst_port == 5004:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.VIDEO_QUEUE))
                out_port =self.add_slice(datapath=datapath, ipv4_src=src,
                                         ipv4_dst=dst, dst_port=dst_port,
                                         weight='video',
                                         queue_id=self.VIDEO_QUEUE,
                                         protocol=protocol, of_priority=3)
            elif dst_port == 10022:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.LATENCY_QUEUE))
                out_port = self.add_slice(datapath=datapath, ipv4_src=src,
                                          ipv4_dst=dst, dst_port=dst_port,
                                          weight='latency',
                                          queue_id=self.LATENCY_QUEUE,
                                          protocol=protocol, of_priority=3)
              # chao'work
            elif dst_port == 10023:
                self.logger.info("Adding slice: Protocol={} Dst_Port={} Queue={}".format(protocol, dst_port, self.AUDIO_QUEUE))
                out_port = self.add_slice(datapath=datapath, ipv4_src=src,
                                      ipv4_dst=dst, dst_port=dst_port,
                                      weight='latency',
                                      queue_id=self.AUDIO_QUEUE,
                                      protocol=protocol, of_priority=3)


        # add broadcast use switch with in_port==2 to set TTL
        # add multicast (not sure how yet)
        else:
            # non-special traffic!
            if dst in self.net and out_port is None:
                out_port = self.add_base_flow(datapath=datapath,
                                              ipv4_src=src,
                                              ipv4_dst=dst)
        if out_port is None:
            self.logger.info("\nERROR: NO FLOWS ADDED!!! SWITCH {} : pkt: \n{}\n".format(dpid, pkt))
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)
