#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
import sys


class SimpleSwitch13(app_manager.RyuApp):
    """
    H1 ²---² S1 ⁴----------³ S4 ²---² H4
             ³                ⁴
             |                |
             |                |
             ⁴                ³
    H2 ²---² S2 ³----------⁴ S3 ²---² H3

    The little numbers are the switch ports.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #latency preferred
        self.mac_to_port = {1:  {"10:10:10:10:10:11": 2,
                                 "10:10:10:10:10:12": 3,
                                 "10:10:10:10:10:13": 3,
                                 "10:10:10:10:10:14": 4},
                            2:  {"10:10:10:10:10:11": 4,
                                 "10:10:10:10:10:12": 2,
                                 "10:10:10:10:10:13": 3,
                                 "10:10:10:10:10:14": 4},
                            3:  {"10:10:10:10:10:11": 3,
                                 "10:10:10:10:10:12": 4,
                                 "10:10:10:10:10:13": 2,
                                 "10:10:10:10:10:14": 3},
                            4:  {"10:10:10:10:10:11": 3,
                                 "10:10:10:10:10:12": 4,
                                 "10:10:10:10:10:13": 3,
                                 "10:10:10:10:10:14": 2}}
        #self.mac_to_port = {}
        self.has_video = []

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("Switch {} ADD_FLOW! priority: {} match: {}, actions: {}".format(datapath.id, priority, match, actions))

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow_udp(self, datapath, out_port, udp_dst, ipv4_dst, priority=2, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP , ip_proto=17, udp_dst=udp_dst, ipv4_dst=ipv4_dst)
        actions = [parser.OFPActionOutput(out_port)]

        self.add_flow(datapath, priority, match, actions)

    def set_video_slice(self, datapath):
        dpid = datapath.id
        self.logger.info("\nSetting Video-Slice")
        if dpid in self.has_video:
            return
        else:
            self.has_video.append(dpid)
        udp_dst = 5004
        tcp_src = 5004
        if dpid == 1:
            self.add_flow_udp(datapath=datapath, out_port=2, udp_dst=udp_dst, ipv4_dst="10.0.0.1", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.2", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.3", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.4", priority=2)
        elif dpid == 2:
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.1", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=2, udp_dst=udp_dst, ipv4_dst="10.0.0.2", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.3", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.4", priority=2)
        elif dpid == 3:
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.1", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.2", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=2, udp_dst=udp_dst, ipv4_dst="10.0.0.3", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.4", priority=2)
        elif dpid == 4:
            self.add_flow_udp(datapath=datapath, out_port=3, udp_dst=udp_dst, ipv4_dst="10.0.0.1", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.2", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=4, udp_dst=udp_dst, ipv4_dst="10.0.0.3", priority=2)
            self.add_flow_udp(datapath=datapath, out_port=2, udp_dst=udp_dst, ipv4_dst="10.0.0.4", priority=2)
        else:
            raise Exception()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("--------INIT SWITCH {} -------------------------".format(datapath.id))
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # try:
        #     for dst in self.mac_to_port[datapath.id]:
        #         actions = [parser.OFPActionOutput(self.mac_to_port[datapath.id][dst])]
        #         match = parser.OFPMatch(eth_dst=dst)
        #         self.add_flow(datapath, 1, match, actions)
        # except KeyError:
        #     self.logger.info("Switch {} not in mac_to_port".format(datapath.id))

        self.set_video_slice(datapath)
        self.logger.info("------------------------------------------------")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.logger.info("------------------------------------------------")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath

        self.logger.info("Switch {}\n".format(datapath.id))

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

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

        # learn a mac address to avoid FLOOD next time.
        # if src not in self.mac_to_port[dpid]:
        #     self.mac_to_port[dpid][src] = in_port
        # else:
        #     self.logger.info("src is in mac_to_port!")

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            match = parser.OFPMatch(eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info("------------------------------------------------")
