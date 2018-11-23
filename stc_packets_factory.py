# _*_ coding: UTF-8 -*-s
'''
created on Oct 28, 2018
@author: zevloy
'''

from stc import STC
from config import init_conf, get_conf
from iptools.ipv4 import ip2long, long2ip
import logging
#from scapy.all import *
from trex_stl_lib.api import *


class STCPacketsFactory(object):
    '''a factory to build Spirent Test Center packets according the traffic config file'''

    def __init__(self):
        self.case_name = ""
        self.num_packets = 1
        self.traffic_config = {}


    def build_stc_eth(self):
        p2 = Ether()

        if "mac_dst" in self.traffic_config:
            p2.dst = self.traffic_config["mac_dst"]
        if "mac_dst" in self.traffic_config:
            p2.src = self.traffic_config["mac_src"]
        #if "l2_encap" in traffic_config:
            #p2.type = int(traffic_config["l2_encap"])
        #ls(p2)
        return p2

    def build_stc_ipv4(self):
        '''L3 packet construction using Stc traffic parameters in traffic_config'''

        p3 = IP()
        #ip.version must be 4 in this function.
        p3.version == 4
        if "ip_hdr_length" in self.traffic_config:
            p3.ihl = int(self.traffic_config["ip_hdr_length"])
        if "ip_tos_field" in self.traffic_config:
            p3.tos = int(self.traffic_config["ip_tos_field"])
        if "l3_length" in self.traffic_config:
            p3.len = int(self.traffic_config["l3_length"])
        if "ip_id" in self.traffic_config:
            p3.id = int(self.traffic_config["ip_id"])
        if "ip_precedence" in self.traffic_config:
            p3.flags = int(self.traffic_config["ip_precedence"])
        if "ip_fragment_offset" in self.traffic_config:
            p3.frag = int(self.traffic_config["ip_fragment_offset"])
        if "ip_ttl" in self.traffic_config:
            p3.ttl = int(self.traffic_config["ip_ttl"])
        if "ip_protocol" in self.traffic_config:
            p3.proto = int(self.traffic_config["ip_protocol"])
        if "ip_dst_addr" in self.traffic_config:
            p3.dst = self.traffic_config["ip_dst_addr"]
        if "ip_src_addr" in self.traffic_config:
            p3.src = self.traffic_config["ip_src_addr"]

        return p3

    def build_stc_ipv6(self):
        p3 = IPv6()
        return p3

    def build_stc_tcp(self):
        """L4 TCP packet construction using STC traffic parameters in traffic_config.

        :param f:
        :returns: p4, a tcp instance
        :raises: None
        """
        #TODO:tcp flags should be a int, such as p4.flag = 7 means "FSR"
        p4 = TCP()
        if "tcp_src_port" in self.traffic_config:
            p4.sport = int(self.traffic_config["tcp_src_port"])
        if "tcp_dst_port" in self.traffic_config:
            p4.dport = int(self.traffic_config["tcp_dst_port"])
        if "tcp_seq_num" in self.traffic_config:
            p4.seq = int(self.traffic_config["tcp_seq_num"])
        if "tcp_ack_num" in self.traffic_config:
            p4.ack = int(self.traffic_config["tcp_ack_num"])
        if "tcp_data_offset" in self.traffic_config:
            p4.dataofs = int(self.traffic_config["tcp_data_offset"])
        if "tcp_reserved" in self.traffic_config:
            p4.reserved = int(self.traffic_config["tcp_reserved"])
        if "tcp_window" in self.traffic_config:
            p4.window = int(self.traffic_config["tcp_window"])
        if "tcp_urgent_ptr" in self.traffic_config:
            p4.urgptr = int(self.traffic_config["tcp_urgent_ptr"])

        return p4

    #TODO
    def build_stc_udp(self):
        p4 = UDP()
        return p4

    def _create_stc_packets(self):
        '''create a stl stream base on scapy packet template'''

        p2 = self.build_stc_eth()

        if "l3_protocol" in self.traffic_config:
            if self.traffic_config["l3_protocol"] == "ipv4":
                p3 = self.build_stc_ipv4()
            elif self.traffic_config["l3_protocol"] == "ipv6":
                p3 = self.build_stc_ipv6()
            else:
                logging.error("layer 3 version must be 4 or 6")

        if "ip_protocol" in self.traffic_config:
            if self.traffic_config["ip_protocol"] == '6':
                p4 = self.build_stc_tcp()
            elif self.traffic_config["ip_protocol"] == '17':
                p4 = self.build_stc_udp()
            else:
                logging.error("layer 4 version must be 6 or 17")

        #Layer Beyond the TCP, STC() should only use defaut input parameters
        #since the STC layer is created according to the *traffic_config.xml
        if self.case_name in ["case91"]:
            p5 = STC()
        elif self.case_name in ["case35"]:
            signature = 20*'1'
            p5 = signature + (p3.len - 60)*'0'

        p = p2/p3/p4/p5
        base_pkts = []
        base_pkts.append(p)
        return base_pkts

    def get_stc_packets(self, traffic_config, case_name="case91", num_packets=1, **kwargs):
        self.case_name = case_name
        self.num_packets = num_packets
        self.traffic_config = traffic_config

        return self._create_stc_packets()

if __name__ == '__main__':
    pkt_factory = STCPacketsFactory()

    for p in pkt_factory.get_stc_packets(case_name="case91", traffic_config_file="config/case91_p1_tx_traffic_config.xml", num_packets=1):
        ls(p)

