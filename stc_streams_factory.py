'''
create stateless stream or streams according to the configuration file.
Created on Oct 28, 2018
@author: zevloy
'''

from config import init_conf, get_conf
from iptools.ipv4 import ip2long, long2ip
import logging
import time
#from scapy.all import *
from trex_stl_lib.api import *
from stc_packets_factory import STCPacketsFactory


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='/var/log/z-tester/z_tester.log',
                    filemode='w')


class StcStreamFactory(object):
    '''building streams according the configuration file'''

    def __init__(self, case_name, burst_loop_count, traffic_config_file):
        self.case_name = case_name
        self.burst_loop_count = burst_loop_count
        self.traffic_config_file = traffic_config_file
        self.pg_id = 1
        self.num_streams = 1

        try:
            init_conf(traffic_config_file)
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
            b = StcStreamFactory.get_next_valid_ip(b)
        return b

    @staticmethod
    def get_next_ip(s):
        """ip=ip+1, include x.x.x.0 and x.x.x.255,

        :param s: string type of ip .
        :returns: ip+1
        :raises:
        """
        return str(long2ip(ip2long(s) + 1))

    def get_max_ip(self, min_ip, count):
        """ip = ip + count, include x.x.x.0 and x.x.x.255,

        :param min_ip: first ip of a stream.
        :returns: last ip of a stream
        :raises:
        """
        return str(long2ip(ip2long(min_ip) + int(count) - 1))

    def get_ip_list(self):
        '''create ip address list increase by 1, without invalid ip such as .0 or .255'''

        dst_ip_list = []
        dst_ip = self.traffic_config["ip_dst_addr"]
        dst_ip_list.append(dst_ip)

        for i in range(self.burst_loop_count - 1):
            dst_ip = StcStreamFactory.get_next_valid_ip(dst_ip)
            dst_ip_list.append(dst_ip)

        return dst_ip_list

    def get_ip_src_min_max_value(self):
        '''get ip src max value according to the configuration file'''

        if "ip_src_mode" in self.traffic_config:
            ip_src_min_value = self.traffic_config["ip_src_addr"]
            ip_src_step = self.traffic_config["ip_src_step"]
            ip_src_mode = self.traffic_config["ip_src_mode"]
            ip_src_count = self.traffic_config["ip_src_count"]
            ip_src_repeat_count = self.traffic_config["ip_src_repeat_count"]

            return ip_src_min_value, self.get_max_ip(ip_src_min_value, ip_src_count)
        else: 
            return ip_src_min_value, None #if there is not ip_src_mode, just return two equal values.

    def get_ip_dst_min_max_value(self):
        '''get ip dst max value according to the configuration file'''

        if "ip_dst_mode" in self.traffic_config:
            ip_dst_min_value = self.traffic_config["ip_dst_addr"]
            ip_dst_step = self.traffic_config["ip_dst_step"]
            ip_dst_mode = self.traffic_config["ip_dst_mode"]
            ip_dst_count = self.traffic_config["ip_dst_count"]
            ip_dst_repeat_count = self.traffic_config["ip_dst_repeat_count"]

            return ip_dst_min_value, self.get_max_ip(ip_dst_min_value, ip_dst_count)
        else: 
            return ip_dst_min_value, None #if there is not ip_dst_mode, just return two equal values.

    def get_tcp_src_min_max_value(self):
        '''get maximum tcp src port value according to the config file '''
        if "tcp_src_port_mode" in self.traffic_config:
            tcp_src_min_value = int(self.traffic_config["tcp_src_port"])
            tcp_src_port_step = self.traffic_config["tcp_src_port_step"]
            tcp_src_port_mode = self.traffic_config["tcp_src_port_mode"]
            tcp_src_port_count = self.traffic_config["tcp_src_port_count"]
            tcp_src_port_repeat_count = self.traffic_config["tcp_src_port_repeat_count"]
            return tcp_src_min_value, int(tcp_src_min_value) + int(tcp_src_port_count)
        else:
            return tcp_src_min_value, None #if there is not tcp_src_port_mode, just return two equal values.

    def get_tcp_dst_min_max_value(self):
        '''get maximum tcp dst port value according to the config file '''
        if "tcp_dst_port_mode" in self.traffic_config:
            tcp_dst_min_value = int(self.traffic_config["tcp_dst_port"])
            tcp_dst_port_step = self.traffic_config["tcp_dst_port_step"]
            tcp_dst_port_mode = self.traffic_config["tcp_dst_port_mode"]
            tcp_dst_port_count = self.traffic_config["tcp_dst_port_count"]
            tcp_dst_port_repeat_count = self.traffic_config["tcp_dst_port_repeat_count"]
            return tcp_dst_min_value, int(tcp_dst_min_value) + int(tcp_dst_port_count)
        else:
            return tcp_dst_min_value, None #if there is not tcp_dst_port_mode, just return two equal values.

    def _create_stream(self):
        '''create a stl stream base on scapy packet template'''

        spf = STCPacketsFactory()
        #base_pkt = spf.get_stc_packets(case_name=self.case_name, traffic_config_file=self.traffic_config_file, num_packets=1)
        base_pkt = spf.get_stc_packets(traffic_config=self.traffic_config, case_name=self.case_name, num_packets=1)
        
        #print "self.burst_loop_count", self.burst_loop_count
        #print "self.get_ip_list()", self.get_ip_list()
        #logging.info(ls(base_pkt[0]))
        streams = []
        # build a stream according case91
        if self.case_name in ["case91"]:
            pkt = STLPktBuilder(pkt=base_pkt[0])
            streams.append(STLStream(packet=pkt, mode=STLTXSingleBurst(total_pkts=self.burst_loop_count), flow_stats=STLFlowStats(self.pg_id)))
            return streams
        # build a stream according case35
        elif self.case_name in ["case35", "case36", "case37", "case38", "case39", "case40"]:
            ip_src_min_value, ip_src_max_value = self.get_ip_src_min_max_value()
            ip_dst_min_value, ip_dst_max_value = self.get_ip_src_min_max_value()
            tcp_src_min_value, tcp_src_max_value = self.get_tcp_src_min_max_value()          
            tcp_dst_min_value, tcp_dst_max_value = self.get_tcp_dst_min_max_value()
            
            vmfv = []
            if not ip_src_max_value == None:
                vmfv.append(STLVmFlowVar ( "ip_src", min_value=ip_src_min_value, max_value=ip_src_max_value, size=4, step=1, op="inc"))
                vmfv.append(STLVmWrFlowVar(fv_name="ip_src", pkt_offset="IP.src")) # write ip to packet IP.src
            if not ip_dst_max_value == None:
                vmfv.append(STLVmFlowVar ( "ip_dst", min_value=ip_dst_min_value, max_value=ip_dst_max_value, size=4, step=1, op="inc"))
                vmfv.append(STLVmWrFlowVar(fv_name="ip_dst", pkt_offset="IP.dst")) # write ip to packet IP.src
            if not tcp_src_max_value == None:
                vmfv.append(STLVmFlowVar ( "tcp_src", min_value=tcp_src_min_value, max_value=tcp_src_max_value, size=2, step=1, op="inc"))
                vmfv.append(STLVmWrFlowVar(fv_name="tcp_src", pkt_offset="TCP.sport")) # write sport 
            if not tcp_dst_max_value == None:
                vmfv.append(STLVmFlowVar ( "tcp_dst", min_value=tcp_dst_min_value, max_value=tcp_dst_max_value, size=2, step=1, op="inc"))
                vmfv.append(STLVmWrFlowVar(fv_name="tcp_dst", pkt_offset="TCP.dport")) # write dport 
            vmfv.append(STLVmFixIpv4(offset="IP"))

            vm = STLScVmRaw(vmfv, cache_size=self.burst_loop_count)

            pkt = STLPktBuilder(pkt=base_pkt[0], vm=vm)
            streams.append(STLStream(packet=pkt, mac_dst_override_mode=1, mode=STLTXSingleBurst(total_pkts=self.burst_loop_count), flow_stats=STLFlowStats(self.pg_id)))
            return streams

        #streams.append(STLStream(packet=pkt, mode=STLTXCont()))
        return streams

    def get_streams(self, pg_id=1, num_streams=1, **kwargs):
        self.pg_id = pg_id
        self.num_streams = num_streams
        return self._create_stream()


def burst_streams(port_a, port_b, burst_loop_count, rate, config_file_name, case_name):
    """send ipv4 packets according configuration file.

    :param f: configuration file .
    :returns: None
    :raises: None
    """

    # create client
    c = STLClient()
    passed = True

    try:
        ssf = StcStreamFactory(case_name, burst_loop_count, config_file_name)
        ss = ssf.get_streams(pg_id=1, num_streams=1)
        # connect to server
        c.connect()

        # prepare our ports
        c.reset(ports=[port_a])
        #c.set_port_attr([port_a, port_b], promiscuous = True)
        # add streams to ports
        stream_ids = c.add_streams(ss, ports=[port_a])
        c.clear_stats()
        c.start(ports=[port_a], mult=rate)
        c.wait_on_traffic(ports=[port_a])

        f_log_1 = "/var/log/z-tester/" + case_name + "/traffic_all_" + case_name + ".txt"
        f_log_2 = "/var/log/z-tester/" + case_name + "/pg_stats_" + case_name + ".txt"
        f_log_3 = "/var/log/z-tester/" + case_name + "/streams_" + case_name + ".txt"

        if not os.path.exists(os.path.dirname(f_log_1)):
            try:
                os.makedirs(os.path.dirname(f_log_1))
            except OSError as e: # Guard against race condition
                print "Error: fail to create the log directory."
                print e

        if not os.path.exists(os.path.dirname(f_log_2)):
            try:
                os.makedirs(os.path.dirname(f_log_2))
            except OSError as e: # Guard against race condition
                print "Error: fail to create the log directory."
                print e

        if not os.path.exists(os.path.dirname(f_log_2)):
            try:
                os.makedirs(os.path.dirname(f_log_2))
            except OSError as e: # Guard against race condition
                print "Error: fail to create the log directory."
                print e

        stats = c.get_stats()
        with open(f_log_1, 'w') as f:
            f.write(str(stats))
 
        with open(f_log_2, 'w') as f:  
            f.write(str(c.get_pgid_stats()))
       
        with open(f_log_3, 'w') as f: 
            for s in ss: 
                f.write(s.to_code())

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
    burst_streams(port_a=0, port_b=1, burst_loop_count=1000, rate='1000pps', config_file_name="config/case91_p1_tx_traffic_config.xml", case_name="case91")
    #burst_streams(port_a=0, port_b=1, burst_loop_count=1000, rate='1000pps', config_file_name="config/case37_traffic_config.xml", case_name="case37")
    t1 = time.time()

    logging.info("Time used:, %10.2f seconds used." % (t1 - t0))

