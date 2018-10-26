# -*- coding: UTF-8 -*-s
'''
send spirent test center's traffic according the configuration file, suppose to be called by Intelligent Test System.
Created on Oct 11, 2018
@author: zevloy
'''

from stc_packet import StcPacket
from scapy.all import *
from config import init_conf, get_conf
from iptools.ipv4 import ip2long, long2ip
import logging
import time


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='z-tester.log',
                    filemode='w')

traffic_results_ret = {'status': '0'}


def get_next_valid_ip(s):
    """ip=ip+1, omit x.x.x.0 and x.x.x.255,

    :param s: string type of ip .
    :returns: string type of ip+1
    :raises:
    """
    b = str(long2ip(ip2long(s) + 1))
    if b.split('.')[3] == "0" or b.split('.')[3] == "255":
        b = get_next_valid_ip(b)
    return b


def get_next_ip(s):
    """ip=ip+1, include x.x.x.0 and x.x.x.255,

    :param s: string type of ip .
    :returns: ip+1
    :raises:
    """
    return str(long2ip(ip2long(s) + 1))


def build_stc_eth():
    traffic_config = get_conf()
    p2 = Ether()

    if "mac_dst" in traffic_config:
        p2.dst = traffic_config["mac_dst"]
    if "mac_dst" in traffic_config:
        p2.src = traffic_config["mac_src"]
    #if "l2_encap" in traffic_config:
        #p2.type = int(traffic_config["l2_encap"])
    #ls(p2)
    return p2


def build_stc_ipv4():
    traffic_config = get_conf()
    dst_ip_list = []
    #logging.info(traffic_config)

    #L3 packet construction using Stc traffic parameters in traffic_config
    p3 = IP()

    #ip.version must be 4 in this function.
    p3.version == 4
    if "ip_hdr_length" in traffic_config:
        p3.ihl = int(traffic_config["ip_hdr_length"])
    if "ip_tos_field" in traffic_config:
        p3.tos = int(traffic_config["ip_tos_field"])
    if "l3_length" in traffic_config:
        p3.len = int(traffic_config["l3_length"])
    if "ip_id" in traffic_config:
        p3.id = int(traffic_config["ip_id"])
    if "ip_precedence" in traffic_config:
        p3.flags = int(traffic_config["ip_precedence"])
    if "ip_fragment_offset" in traffic_config:
        p3.frag = int(traffic_config["ip_fragment_offset"])
    if "ip_ttl" in traffic_config:
        p3.ttl = int(traffic_config["ip_ttl"])
    if "ip_protocol" in traffic_config:
        p3.proto = int(traffic_config["ip_protocol"])
    if "ip_dst_addr" in traffic_config:
        p3.dst = traffic_config["ip_dst_addr"]
    if "ip_src_addr" in traffic_config:
        p3.src = traffic_config["ip_src_addr"]

    return p3


def build_stc_ipv6():
    traffic_config = get_conf()    
    p3 = IPv6()
    return p3


def build_stc_tcp():
    """L4 TCP packet construction using Stc traffic parameters in traffic_config.

    :param f:
    :returns: p4, a tcp instance
    :raises: None
    """
    #TODO:tcp flags should be a int, such as p4.flag = 7 means "FSR"
    traffic_config = get_conf()
    p4 = TCP()
    if "tcp_src_port" in traffic_config:
        p4.sport = int(traffic_config["tcp_src_port"])
    if "tcp_dst_port" in traffic_config:
        p4.dport = int(traffic_config["tcp_dst_port"])
    if "tcp_seq_num" in traffic_config:
        p4.seq = int(traffic_config["tcp_seq_num"])
    if "tcp_ack_num" in traffic_config:
        p4.ack = int(traffic_config["tcp_ack_num"])
    if "tcp_data_offset" in traffic_config:
        p4.dataofs = int(traffic_config["tcp_data_offset"])
    if "tcp_reserved" in traffic_config:
        p4.reserved = int(traffic_config["tcp_reserved"])
    if "tcp_window" in traffic_config:
        p4.window = int(traffic_config["tcp_window"])
    if "tcp_urgent_ptr" in traffic_config:
        p4.urgptr = int(traffic_config["tcp_urgent_ptr"])

    return p4


#TODO
def build_stc_udp():
    traffic_config = get_conf()
    p4 = UDP()
    return p4


def send_stc_pkt(f):
    """send ipv4 packets according configuration file.

    :param f: configuration file .
    :returns: None
    :raises: None
    """
    init_conf(f)
    traffic_config = get_conf()
    dst_ip_list = []

    global traffic_results_ret

    p2 = build_stc_eth()

    if "l3_protocol" in traffic_config:
        if traffic_config["l3_protocol"] == "ipv4":
            p3 = build_stc_ipv4()
        elif traffic_config["l3_protocol"] == "ipv6":
            p3 = build_stc_ipv6()
        else:
            logging.error("layer 3 version must be 4 or 6")
            traffic_results_ret['status'] = '0'

    if "ip_protocol" in traffic_config:
        if traffic_config["ip_protocol"] == '6':
            p4 = build_stc_tcp()
        elif traffic_config["ip_protocol"] == '17':
            p4 = build_stc_udp()
        else:
            logging.error("layer 4 version must be 6 or 17")
            traffic_results_ret['status'] = '0'
    #Layer Beyond the TCP, StcPacket() should only use defaut input parameters
    #since the StcPacket layer is created according to the *traffic_config.xml

    p5 = StcPacket()

    #TODO:should fetch burst_loop_count from *_p1_tx.py
    burst_loop_count = 1000

    dst_ip = traffic_config["ip_dst_addr"]
    dst_ip_list.append(dst_ip)

    for i in range(burst_loop_count - 1):
        dst_ip = get_next_valid_ip(dst_ip)
        dst_ip_list.append(dst_ip)

    p3.dst = dst_ip_list

    p = p2/p3/p4/p5
    packetList = sendp(p, return_packets=True)
    #print packetList.summary()

    traffic_results_ret['status'] = '1'


def traffic_stats(port_handle, mode):
    """check the stats after packet sent, suppose to be called after send_stc_pkt().

    :param port_handle: Tester Center's port, just negelected.
    :param mode:
    :returns: traffic result, the 'status' is used to determin if the tranffic sending successs.
    :raises: None
    """
    return traffic_results_ret


if __name__ == '__main__':

    import cProfile
    import pstats

    t0 = time.time()
    #use cProfile to evaluate the program's performance.
    cProfile.run('''send_stc_pkt(f="StcConf/case91_p1_tx_traffic_config.xml")''', filename="result.out", sort="cumulative")
    t1 = time.time()

    logging.info("send 1000 packets with dst ip list, %10.2f seconds used." % (t1 - t0))

    p = pstats.Stats("result.out")
    #p.strip_dirs().sort_stats(-1).print_stats()
    p.strip_dirs().sort_stats("time", "name").print_stats()

    
    #TODO:should fetch burst_loop_count from *_p1_tx.py
    burst_loop_count = 1000
    dst_ip_list = []
    dst_ip = "1.1.1.1"
    dst_ip_list.append(dst_ip)

    for i in range(burst_loop_count - 1):
        dst_ip = get_next_valid_ip(dst_ip)
        dst_ip_list.append(dst_ip)

    t0 = time.time()
    #use cProfile to evaluate the program's performance.
    sendp(IP(dst=dst_ip_list, len=1500)/TCP())
    t1 = time.time()

    logging.info("send 1000 regular IP packets %10.2f seconds used." % (t1 - t0))
