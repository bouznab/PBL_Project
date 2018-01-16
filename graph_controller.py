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

        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i = 0
        self.logger.info("**********ProjectController __init__")

    def printG(self):
        G = self.net
        self.logger.info("G")
        self.logger.info("nodes", G.nodes())  # 输出全部的节点： [1, 2, 3]
        self.logger.info("edges", G.edges()) # 输出全部的边：[(2, 3)]
        self.logger.info("number_of_edges", G.number_of_edges()) # 输出边的数量：1
        for e in G.edges():
            self.logger.info(G.get_edge_data(e[0], e[1]))

    # Handy function that lists all attributes in the given object
    def ls(self, obj):
        self.logger.info("\n".join([x for x in dir(obj) if x[0] != "_"]))

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

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("\n-----------get_topology_data")

        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        self.logger.info("-----------List of switches")
        for switch in switch_list:
            # self.ls(switch)
            self.logger.info(switch)
            # self.nodes[self.no_of_nodes] = switch
            # self.no_of_nodes += 1

        # -----------------------------
        links_list = get_link(self.topology_api_app, None)
        # for link in links_list:
        #     self.logger.info(link)
        # self.logger.info(links_list)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        # self.logger.info(links)
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        # self.logger.info(links)
        self.net.add_edges_from(links)
        self.logger.info("-----------List of links")
        self.logger.info(self.net.edges())

        # self.printG()
        # the spectral layout
        # pos = nx.spectral_layout(G)
        # draw the regular graph
        # nx.draw(G)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_dst=dst)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY, instructions=inst)
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

        self.logger.info("nodes")
        self.logger.info(self.net.nodes())
        self.logger.info("edges")
        self.logger.info(self.net.edges())
        self.logger.info("packet in switch:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0)
            self.net.add_edge(src, dpid, weight=0)
        if dst in self.net:
            # self.logger.info(src in self.net)
            # self.logger.info(nx.shortest_path(self.net,1,4))
            # self.logger.info(nx.shortest_path(self.net,4,1))
            # self.logger.info(nx.shortest_path(self.net,src,4))
            # G= self.net
            # G[1][2]['weight'] = 100
            # G[2][1]['weight'] = 100
            # G[2][3]['weight'] = 100
            # G[3][2]['weight'] = 100
            #
            # G[1][4]['weight'] = 10
            # G[4][1]['weight'] = 10
            # G[4][5]['weight'] = 10
            # G[5][4]['weight'] = 10
            # G[5][3]['weight'] = 10
            # G[3][5]['weight'] = 10
            # self.printG()

            try:
                path = nx.shortest_path(self.net, src, dst, weight="weight")
                next = path[path.index(dpid) + 1]
                out_port = self.net[dpid][next]['port']
            except Exception as e:
                #self.logger.info(e)
                pass
            # self.logger.info(path)
            # self.logger.info(G[path[0]][path[1]])
            # self.logger.info(G[path[-2]][path[-1]])
            # self.logger.info("dpid=", str(dpid))
            #self.logger.info("length=", nx.shortest_path_length(self.net, src, dst, weight="weight"))
            out_port = 100

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
