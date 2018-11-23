# -*- coding: UTF-8 -*-s
'''
Implementation of the configuration related job.

Created on Oct 9, 2018
@author: zevloy
'''

import logging

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


interface_config = {}
traffic_config = {}


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
    
    try:
        #use ET to parse a parameter xml file
        tree = ET.parse(filename)
        #build a traffic config dictionary
    except Exception as e:
        logging.error(e)
        logging.error("Error: cannot parse file {%s}." % filename)

    traffic_config = _etree_to_dict(tree)


def get_conf():
    return traffic_config


def get_stcPacket_conf():
    '''fetch the parameters used by stcPacket layer, such as "custom_pattern"'''

    init_conf("config/case91_p1_tx_traffic_config.xml")

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

    init_conf("config/case91_p1_tx_traffic_config.xml")
    print get_conf()

    custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length = get_stcPacket_conf()
    print custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length
