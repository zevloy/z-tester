# -*- coding: UTF-8 -*-s
'''
Implementation of the configuration related job.

Created on Oct 9, 2018
@author: zevloy
'''
import re
import mmap
import logging

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename='myapp.log',
                    filemode='w'
                    )

interface_config = {}
traffic_config = {}


#在caseXX_p1_tx.py脚本中提取int 0端口配置所需的参数，生成对应的xml参数文件。
def make_interface_config_xml():
    f = open(r'StcConf\case91_p1_tx.py', 'r+')
    data = mmap.mmap(f.fileno(), 0)
    f.close()

    interface_config_xml = ET.Element("interface_config")

    pattern = re.compile(r'int_ret0 = sth.interface_config(.?)\((.*?)\)', re.S)
    mo = re.search(pattern, data)

    a = mo.group()
    logging.debug(a)

    b = a.replace('int_ret0 = sth.interface_config (', '')
    logging.debug(b)

    c = b.replace(')', '').replace('\r', '').replace('\n', '').replace('\t', '')
    #print c.split(',')

    for d in c.split(','):
        e = d.split('=')
        #print e
        f = e[0].replace(' ', '').replace('\'', '')
        g = e[1].replace(' ', '').replace('\'', '')
        interface_config[f] = g

    logging.info(interface_config)

    for name, value in interface_config.items():
        ET.SubElement(interface_config_xml, name).text = value

    tree = ET.ElementTree(interface_config_xml)
    f_xml = file("case91_interface_config.xml", 'w')
    tree.write(f_xml)
    f_xml.close()


#在caseXX_p1_tx.py脚本中提取发包所需的参数，生成对应的xml参数文件。
def make_traffic_config_xml():
    f = file(r'StcConf\case91_p1_tx.py', "r")
    data = f.read()
    f.close()

    root = ET.Element("traffic_config")

    #正则表达式，用来提取脚本中对应参数的代码片段
    pattern = re.compile(r'streamblock_ret1 = sth.traffic_config(.?)\((.*?)\)', re.S)
    mo = re.search(pattern, data)

    a = mo.group()
    logging.info(a)

    #把代码片段中的无关的字符去掉
    b = a.replace('streamblock_ret1 = sth.traffic_config (', '')
    logging.info(b)

    c = b.replace(')', '').replace('\r', '').replace('\n', '').replace('\t', '')
    logging.info(c)

    for d in c.split(','):
        e = d.split('=')
        logging.info(e)
        f = e[0].replace(' ', '').replace('\'', '')
        g = e[1].replace(' ', '').replace('\'', '')

        #提取参数后加入字典
        traffic_config[f] = g

    logging.info(traffic_config)

    eth = ET.SubElement(root, "ethernet")
    ip = ET.SubElement(root, "ip")
    tcp = ET.SubElement(root, "tcp")
    stc = ET.SubElement(root, "stc_layer")
    other = ET.SubElement(root, "other")

    #提取字典中的key-value，做成xml格式的文件。
    for name, value in traffic_config.items():
        if name in ["l2_encap", "mac_src", "mac_dst", "frame_size"]:
            ET.SubElement(eth, name).text = value
        elif name in ["ip_hdr_length", "ip_tos_field", "ip_id", "l3_protocol", "ip_ttl", "ip_fragment_offset", "ip_protocol", "l3_length", "ip_mbz", "ip_src_addr", "ip_dst_addr", "ip_precedence"]:
            ET.SubElement(ip, name).text = value
        elif name in ["tcp_src_port", "tcp_dst_port", "tcp_urgent_ptr", "tcp_checksum", "tcp_ack_flag", "tcp_data_offset", "tcp_ack_num", "tcp_fin_flag", "tcp_urg_flag", "tcp_window", "l4_protocol", "tcp_reserved", "tcp_reserved", "tcp_seq_num", "tcp_psh_flag", "tcp_syn_flag", "tcp_rst_flag"]:
            ET.SubElement(tcp, name).text = value
        elif name in ["custom_pattern", "disable_signature", "fill_value"]:
            ET.SubElement(stc, name).text = value
        else:
            ET.SubElement(other, name).text = value

    tree = ET.ElementTree(root)
    f_xml = file("StcConf\case91_traffic_config.xml", 'w')
    tree.write(f_xml)
    f_xml.close()


def _etree_to_dict(t):
        '''convert traffic parameters from an element tree obj to a dictionary'''
        root = t.getroot()
        data_dict = {}
        for child in root:
            for item in child:
                data_dict[item.tag] = item.text
        return data_dict


def init_conf(filename):
    '''Take out the parameters from a configuration file such case91_traffic_config.xml '''
    global traffic_config
    #use ET to parse a parameter xml file
    tree = ET.parse(filename)
    #build a traffic config dictionary
    traffic_config = _etree_to_dict(tree)


def get_conf():
    return traffic_config


def get_stcPacket_conf():
    '''fetch the parameters used by stcPacket layer, such as "custom_pattern"'''
    global traffic_config

    #TODO: Check why there is a \n left
    custom_pattern = traffic_config['custom_pattern'].replace("\n", "")
    l3_length = int(traffic_config['l3_length'])

    if traffic_config['disable_signature'] == '0':
        signature_length = 20
    else:
        signature_length = 0

    custom_pattern_length = len(custom_pattern)
    padding_length = l3_length - custom_pattern_length - signature_length - 40

    return custom_pattern, signature_length, l3_length-40, custom_pattern_length, padding_length


if __name__ == '__main__':
    make_traffic_config_xml()

    init_conf("StcConf\case91_traffic_config.xml")
    print get_conf()

    custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length = get_stcPacket_conf()
    print custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length
