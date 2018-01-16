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
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches

import networkx as nx


class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.net = nx.DiGraph()
        self.net.add_node(1)
        self.net.add_node(2)
        self.net.add_node(3)
        self.net.add_node(4)
        self.net.add_edge(1, 2, port=3, weight_video=20, weight_latency=1)
        self.net.add_edge(2, 1, port=4, weight_video=20, weight_latency=1)
        self.net.add_edge(2, 3, port=3, weight_video=1, weight_latency=20)
        self.net.add_edge(3, 2, port=4, weight_video=1, weight_latency=20)
        self.net.add_edge(3, 4, port=3, weight_video=1, weight_latency=20)
        self.net.add_edge(4, 3, port=4, weight_video=1, weight_latency=20)
        self.net.add_edge(4, 1, port=3, weight_video=1, weight_latency=20)
        self.net.add_edge(1, 4, port=4, weight_video=1, weight_latency=20)
        path = nx.shortest_path(self.net, 1, 2, 'weight_video')
        self.logger.info("VIDEO: SHORTEST PATH FROM s1 to s2: \n{}".format(path))
        path = nx.shortest_path(self.net, 1, 2, 'weight_latency')
        self.logger.info("LATENCY: SHORTEST PATH FROM s1 to s2: \n{}".format(path))
        self.logger.info("**********ProjectController __init__")

    # Handy function that lists all attributes in the given object
    # def ls(self, obj):
    #     self.logger.info("\n".join([x for x in dir(obj) if x[0] != "_"]))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("\n-----------switch_features_handler is called")

        msg = ev.msg
        self.logger.info('OFPSwitchFeatures received: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (
            msg.datapath_id, msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities))

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=0, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("switch_features_handler is over")

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
        match = datapath.ofproto_parser.OFPMatch(eth_dst=dst)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
        self.logger.info("Adding flow: {}".format(mod))
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.info("**********_packet_in_handler")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # print some info about incoming packet to get a feel for controller traffic
        # layer = 0
        # for p in pkt.protocols:
        #     self.logger.info("..................\nlayer {}".format(layer))
        #     try:
        #         if p.protocol_name:
        #             self.logger.info("{} Packet:".format(p.protocol_name))
        #     except Exception:
        #         pass
        #     try:
        #         if p.protocol_name and p.src and p.dst:
        #             self.logger.info("from: {} | to {}".format(p.src, p.dst))
        #             if layer > 0:
        #                 try:
        #                     self.logger.info("p._TYPES[p.proto]: {}".format(p._TYPES[p.proto]))
        #                 except Exception:
        #                     self.logger.info("No special protocol")
        #     except Exception:
        #         pass
        #     if layer == 2:
        #         try:
        #             self.logger.info("UDP dst_port: {}".format(p.dst_port))
        #         except Exception:
        #             self.logger.info("NOT UDP: type(p)={}".format(type(p)))
        #     layer += 1
        # self.logger.info("..................")

        if src not in self.net:
            self.logger.info("adding {} to graph".format(src))
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight_video=0, weight_latency=0)
            self.net.add_edge(src, dpid, weight_video=0, weight_latency=0)
        if dst in self.net:
            try:
                path = nx.shortest_path(self.net, src, dst, weight="weight_latency")
                next = path[path.index(dpid) + 1]
                out_port = self.net[dpid][next]['port']
                self.logger.info(path)
            except Exception as e:
                self.logger.info("NO SHORTEST PATH")
                out_port = ofproto.OFPP_FLOOD

        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)
