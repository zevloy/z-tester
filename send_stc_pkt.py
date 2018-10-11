# -*- coding: UTF-8 -*-s
'''
send spirent test center's traffic according the configuration file, suppose to be called by Intelligent Test System.
Created on Oct 2, 2018
@author: zevloy
'''

from stc_packet import StcPacket
from scapy.all import *
from config import init_conf, get_conf
from iptools.ipv4 import ip2long, long2ip


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
    """ip=ip+1, include x.x.x.0 and x.x.x.255,

    :param s: string type of ip .
    :returns: ip+1
    :raises:
    """
    #TODO:convert the IP option field from Stc to scapy format.
    #ip_opt = 0
    #TODO:convert the TCP option field from Stc to scapy format.
    #tcp_opt = 0

    init_conf(f)
    traffic_config = get_conf()
    print traffic_config

    #p = IP()/TCP()/StcPacket(StcSignature="1234567890"*2, StcPadding="0"*1264, CustomPattern="1"*176)

    #convert the ip version field from "ipv4" to 4.
    ip_ver = 0
    if traffic_config["l3_protocol"] == "ipv4":
        ip_ver = 4

    #L3 packet construction using Stc traffic parameters in traffic_config
    p3 = IP(
        version=int(ip_ver),
        ihl=int(traffic_config["ip_hdr_length"]),
        tos=int(traffic_config["ip_tos_field"]),
        len=int(traffic_config["l3_length"]),
        id=int(traffic_config["ip_id"]),
        flags=int(traffic_config["ip_precedence"]),
        frag=int(traffic_config["ip_fragment_offset"]),
        ttl=int(traffic_config["ip_ttl"]),
        proto=int(traffic_config["ip_protocol"]),
        #chksum=int(traffic_config["l3_length"]),
        dst=traffic_config["ip_dst_addr"],
        src=traffic_config["ip_src_addr"]
        #options=tcp_opt
        )

    #L4 packet construction using Stc traffic parameters in traffic_config
    p4 = TCP(
        sport=int(traffic_config["tcp_src_port"]),
        dport=int(traffic_config["tcp_dst_port"]),
        seq=int(traffic_config["tcp_seq_num"]),
        ack=int(traffic_config["tcp_ack_num"]),
        dataofs=int(traffic_config["tcp_data_offset"]),
        reserved=int(traffic_config["tcp_reserved"]),
        flags=int(traffic_config["tcp_ack_flag"]),
        window=int(traffic_config["tcp_window"]),
        #chksum=int(traffic_config[""]),
        urgptr=int(traffic_config["tcp_urgent_ptr"])
        #options=[1, 2, 3, 4]
        )

    # StcPacket() should only use defaut input parameters since the StcPacket layer is created according to the *traffic_config.xml
    p5 = StcPacket()

    p = p3/p4/p5
    ls(p)
    p.show()

    #TODO:should fetch burst_loop_count from *_p1_tx.py
    burst_loop_count = 1

    dst_ip = traffic_config["ip_dst_addr"]
    send(p)

    for i in range(burst_loop_count-1):
        dst_ip = get_next_valid_ip(dst_ip)
        p.dst = dst_ip
        #send(p)

if __name__ == '__main__':
    send_stc_pkt()
