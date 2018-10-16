# -*- coding: UTF-8 -*-s
'''
recv spirent test center's traffic according the configuration file, suppose to be called by Intelligent Test System.
Created on Oct 11, 2018
@author: zevloy
'''


from stc_packet import StcPacket
from scapy.all import *
import logging


def stc_monitor_callback(pkt):
    if StcPacket in pkt:
        pkt.show()


def recv_stc_pkt():
    pass


if __name__ == '__main__':
    p = sniff(count=1)
    p.show()

    pkts = sniff(prn=stc_monitor_callback, filter="StcPacket", store=0, count=10)
    wrpcap("temp.cap", pkts)
    logging.info("writen to temp.pcap")
