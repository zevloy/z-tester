# -*- coding: UTF-8 -*-s
'''
utils mainly for creating configuration file based on the caseXX_p1_tx.py,
take out this fuction from the config.py because it's kind of indepedent tools and
can be modified to create the configuraiton files of all the Case at one time.

Created on Oct 16, 2018
@author: zevloy
'''
import re
import mmap
import logging

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def make_interface_config_xml(f="StcConf/case91_p1_tx.py"):
    '''fetch paremeters about interface from script such as caseXX_p1_tx.py and generate an xml paremeter file'''

    interface_config = {}

    #file mode must be 'r' incase mess the case91_p1_tx.py up
    f = file(f, "r")
    data = f.read()
    f.close()

    interface_config_xml = ET.Element("interface_config")

    pattern = re.compile(r'int_ret0 = sth.interface_config(.?)\((.*?)\)', re.S)
    mo = re.search(pattern, data)

    a = mo.group()
    #logging.debug(a)

    b = a.replace('int_ret0 = sth.interface_config (', '')
    #logging.debug(b)

    c = b.replace(')', '').replace('\r', '').replace('\n', '').replace('\t', '')

    for d in c.split(','):
        e = d.split('=')
        f = e[0].replace(' ', '').replace('\'', '')
        g = e[1].replace(' ', '').replace('\'', '')
        interface_config[f] = g

    logging.info(interface_config)

    for name, value in interface_config.items():
        ET.SubElement(interface_config_xml, name).text = value

    tree = ET.ElementTree(interface_config_xml)
    f_xml = file("StcConf/case91_interface_config.xml", 'w')
    tree.write(f_xml,  encoding="UTF-8", xml_declaration="traffic configuration file", method="xml")
    f_xml.close()


def make_traffic_config_xml(f='StcConf/case91_p1_tx.py'):
    '''fetch paremeters about traffic from script such as caseXX_p1_tx.py and generate an xml paremeter file'''

    traffic_config = {}

    #file mode must be 'r' incase mess the case91_p1_tx.py up
    f = file(f, "r")
    data = f.read()
    f.close()

    root = ET.Element("traffic_config")

    #regex used to take out real paremeters
    pattern = re.compile(r'streamblock_ret1 = sth.traffic_config(.?)\((.*?)\)', re.S)
    mo = re.search(pattern, data)

    a = mo.group()
    #logging.info(a)

    #omit irrelevent part
    b = a.replace('streamblock_ret1 = sth.traffic_config (', '')
    #logging.info(b)

    c = b.replace(')', '').replace('\r', '').replace('\n', '').replace('\t', '')
    #logging.info(c)

    for d in c.split(','):
        e = d.split('=')
        #logging.info(e)
        f = e[0].replace(' ', '').replace('\'', '')
        g = e[1].replace(' ', '').replace('\'', '')

        #fetch paremeter and added into dictionary
        traffic_config[f] = g

    eth = ET.SubElement(root, "ethernet_layer")
    ip = ET.SubElement(root, "ip_layer")
    tcp = ET.SubElement(root, "tcp_layer")
    stc = ET.SubElement(root, "stc_layer")
    other = ET.SubElement(root, "other")

    #take out key-value pair from dictionary and make it a xml file, xml file should be categorized into different parts.
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
    f_xml = file("StcConf/case91_traffic_config.xml", 'w')
    tree.write(f_xml, encoding="UTF-8", xml_declaration="traffic configuration file", method="xml")
    f_xml.close()

if __name__ == '__main__':
    make_traffic_config_xml()
    make_interface_config_xml()
