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
import time, sys


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='myapp.log',
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


def send_stc_pkt_ipv4(f):
    """send ipv4 packets according configuration file.

    :param f: configuration file .
    :returns: None
    :raises: None
    """

    traffic_config = get_conf()
    dst_ip_list = []
    #logging.info(traffic_config)

    #return a dictionary
    global traffic_results_ret

    #L3 packet construction using Stc traffic parameters in traffic_config
    p3 = IP()

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

    #ip.version must be 4 in this function.
    p3.version == 4

    #L4 packet construction using Stc traffic parameters in traffic_config
    #TODO:tcp flags should be a int, such as p4.flag = 7 means "FSR"
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

    # Layer Beyond the TCP, StcPacket() should only use defaut input parameters
    #since the StcPacket layer is created according to the *traffic_config.xml
    p5 = StcPacket()

    p = p3/p4/p5

    #TODO:should fetch burst_loop_count from *_p1_tx.py
    burst_loop_count = 1000

    dst_ip = traffic_config["ip_dst_addr"]
    dst_ip_list.append(dst_ip)

    for i in range(burst_loop_count - 1):
        dst_ip = get_next_valid_ip(dst_ip)
        dst_ip_list.append(dst_ip)

    p.dst = dst_ip_list
    packetList = sendp(p, return_packets=True)
    print packetList.summary()

    traffic_results_ret['status'] = '1'


def send_stc_pkt_ipv6(f):
    pass


def send_stc_pkt(f):
    """check l3 protocol and call the send_stc_pkt_ipv4 or send_stc_pkt_ipv6 accordingly"""    

    init_conf(f)
    traffic_config = get_conf()

    if "l3_protocol" in traffic_config:
        if traffic_config["l3_protocol"] == "ipv4":
            send_stc_pkt_ipv4(traffic_config)
        elif traffic_config["l3_protocol"] == "ipv6":
            send_stc_pkt_ipv6(traffic_config)
        else:
            logging.error("layer 3 version must be 4 or 6")
            traffic_results_ret['status'] = '0'


def traffic_stats(port_handle, mode):
    """check the stats after packet sent, suppose to be called after send_stc_pkt().

    :param port_handle: Tester Center's port, just negelected.
    :param mode:
    :returns: traffic result, the 'status' is used to determin if the result of tranffic sending.
    :raises: None
    """
    return traffic_results_ret


if __name__ == '__main__':

    import cProfile
    import pstats

    pkt = IP()/TCP()
    t0 = time.time()
    rp = sendp(pkt, count=1000, loop=1, return_packets=True)
    t1 = time.time()
    print "send 1000 packets with loop parameters, %10.2f seconds." % (t1-t0)
    print rp.summary()

    t0 = time.time()
    #use cProfile to evaluate the program's performance.
    cProfile.run('''send_stc_pkt(f="StcConf/case91_p1_tx_traffic_config.xml")''', filename="result.out", sort="cumulative")
    t1 = time.time()

    p = pstats.Stats("result.out")
    #p.strip_dirs().sort_stats(-1).print_stats()
    p.strip_dirs().sort_stats("cumulative", "name").print_stats(0.5)
