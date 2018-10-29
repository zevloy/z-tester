
'''
create a stateless stream according to the configuration file.
Created on Oct 28, 2018
@author: zevloy
'''

from stc_packet import StcPacket
from config import init_conf, get_conf
from iptools.ipv4 import ip2long, long2ip
import logging
import time
#from scapy.all import *
from trex_stl_lib.api import *


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='z-tester.log',
                    filemode='w')


class StcStlStream(object):
    '''building streams according the configuration file'''

    def __init__(self, case_name, burst_loop_count, stream_config_file):
        self.case_name = case_name
        self.burst_loop_count = burst_loop_count
        self.stream_config_file = stream_config_file

        try:
            init_conf(stream_config_file)
            self.traffic_config = get_conf()
        except Exception as e:
            print "Error: fail to create a stream."
            print e

    @staticmethod
    def get_next_valid_ip(s):
        """ip=ip+1, omit x.x.x.0 and x.x.x.255,

        :param s: string type of ip .
        :returns: string type of ip+1
        :raises:
        """
        b = str(long2ip(ip2long(s) + 1))
        if b.split('.')[3] == "0" or b.split('.')[3] == "255":
            b = StcStlStream.get_next_valid_ip(b)
        return b

    @staticmethod
    def get_next_ip(s):
        """ip=ip+1, include x.x.x.0 and x.x.x.255,

        :param s: string type of ip .
        :returns: ip+1
        :raises:
        """
        return str(long2ip(ip2long(s) + 1))

    def get_ip_list(self):
        '''create ip address list increase by 1, without invalid ip such as .0 or .255'''

        dst_ip_list = []
        dst_ip = self.traffic_config["ip_dst_addr"]
        dst_ip_list.append(dst_ip)

        for i in range(self.burst_loop_count - 1):
            dst_ip = StcStlStream.get_next_valid_ip(dst_ip)
            dst_ip_list.append(dst_ip)

        return dst_ip_list

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

        #L3 packet construction using Stc traffic parameters in traffic_config
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
        """L4 TCP packet construction using Stc traffic parameters in traffic_config.

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

    def create_stream(self):
        '''create a stl stream base on scapy packet template'''

        p2 = Ether()

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

        #Layer Beyond the TCP, StcPacket() should only use defaut input parameters
        #since the StcPacket layer is created according to the *traffic_config.xml
        p5 = StcPacket()

        base_pkt = p2/p3/p4/p5
        ls(base_pkt)
        print self.burst_loop_count
        print self.get_ip_list()


        vm = STLScVmRaw([STLVmFlowVar("ip_dst", value_list=self.get_ip_list(), op="inc"),
                         #STLVmFlowVar ( "ip_dst", min_value="10.0.0.1", max_value="10.0.0.255", size=4, step=1, op="inc"),
                         STLVmWrFlowVar(fv_name="ip_dst", pkt_offset="IP.dst"),  # write ip to packet IP.src
                         STLVmFixIpv4(offset="IP")  # fix checksum
                         ],
                        #split_by_field="ip_dst",
                        cache_size=self.burst_loop_count  # cache the packets, much better performance
                        )

        pkt = STLPktBuilder(pkt=base_pkt, vm=vm)
        stream = STLStream(packet=pkt, mode=STLTXCont())
        #print(stream.to_code())

        return stream

    def get_streams(self, direction=0, **kwargs):
        # create 1 stream
        return [self.create_stream()]


def simple_burst(port_a, port_b, burst_size, rate, f):
    """send ipv4 packets according configuration file.

    :param f: configuration file .
    :returns: None
    :raises: None
    """

    # create client
    c = STLClient()
    passed = True

    try:
        s = StcStlStream("case91", burst_size, f)
        s1 = s.get_streams()
        # connect to server
        c.connect()

        # prepare our ports
        c.reset(ports=[port_a, port_b])

        # add both streams to ports
        stream_ids = c.add_streams(s1, ports=[port_a])
        c.clear_stats()
        c.start(ports=[port_a], mult=rate, duration=10)
        c.wait_on_traffic(ports=[port_a], rx_delay_ms=1000)

        stats = c.get_stats()
        print stats

        print c.get_active_pgids()
        print c.get_pgid_stats()

        ipackets = stats['total']['ipackets']

        print("Packets Received: ", ipackets)

    except STLError as e:
        passed = False
        print(e)

    finally:
        c.disconnect()

    if c.get_warnings():
            print("\n\n*** test had warnings ****\n\n")
            for w in c.get_warnings():
                print(w)

    if passed and not c.get_warnings():
        print("\nTest has passed :-)\n")
    else:
        print("\nTest has failed :-(\n")


if __name__ == '__main__':

    t0 = time.time()
    simple_burst(0, 1, 1000, '10pps', f="config/case91_p1_tx_traffic_config.xml")
    t1 = time.time()

    logging.info("send 1000 packets with dst ip list, %10.2f seconds used." % (t1 - t0))

