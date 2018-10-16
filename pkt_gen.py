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


logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='myapp.log',
                filemode='w')

traffic_results_ret = {'status' : '0'}

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


def send_stc_pkt(f="StcConf\case91_traffic_config.xml"):
    """send packet according configuration file.

    :param f: configuration file .
    :returns: None
    :raises: None
    """
    #TODO:convert the IP option field from Stc to scapy format.
    #ip_opt = 0
    #TODO:convert the TCP option field from Stc to scapy format.
    #tcp_opt = 0

    init_conf(f)
    traffic_config = get_conf()
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
    if "l3_protocol" in traffic_config:
        if traffic_config["l3_protocol"] == "ipv4":
            p3.version == 4
        elif traffic_config["l3_protocol"] == "ipv6":
            p3.version == 6
        else:
            logging.error("layer 3 version must be 4 or 6")

    #L4 packet construction using Stc traffic parameters in traffic_config
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

    # Layer Beyond the TCP, StcPacket() should only use defaut input parameters since the StcPacket layer is created according to the *traffic_config.xml
    p5 = StcPacket()

    p = p3/p4/p5
    ls(p)
    p.show()

    #TODO:should fetch burst_loop_count from *_p1_tx.py
    burst_loop_count = 5

    try:
        dst_ip = traffic_config["ip_dst_addr"]
        send(p)

        for i in range(burst_loop_count - 1):
            dst_ip = get_next_valid_ip(dst_ip)
            p.dst = dst_ip
            #send(p)
    except Exception, e:
        logging.error(e)
    else:
        traffic_results_ret['status': '1']


def traffic_stats(port_handle, mode):
    """check the stats after packet sent, suppose to be called after send_stc_pkt().

    :param port_handle: Tester Center's port, just 
    :param mode: negelected
    :returns: traffic result, the 'status' is used to determin if the result of tranffic sending.
    :raises: None
    """
    return traffic_results_ret


if __name__ == '__main__':
    try:
        send_stc_pkt()
        logging.info("DONE")
    except Exception, e:
        print False
    else:
        print True