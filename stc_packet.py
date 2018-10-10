# _*_ coding: UTF-8 -*-s
'''
Created on Oct 2, 2018

@author: zevloy
'''

from scapy.all import *
import xml.etree.ElementTree as ET
from config import init_conf, get_stcPacket_conf



class StcPacket(Packet):
    """define a sprirent test center kind of Packet Class"""

    name = "StcPacket"

    init_conf("case91_traffic_config.xml")
    custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length = get_stcPacket_conf()

    fields_desc = [StrField("StcSignature", '0'*signature_length, fmt="H"), StrField("StcPadding", '0'*padding_length, fmt="H"), StrField("CustomPattern", '1'*custom_pattern_length, fmt="H")]

    def guess_payload_class(self, payload):
        ''' Decides if the payload contain the Custom pattern'''    
        if payload.endswith(self.custom_pattern):
            return StcPacket
        else:
            return Packet.guess_payload_class(self, payload)

    def do_dissect(self, s):
        ''' From the Stc packet string, populate the scapy object '''


        self.setfieldval('StcSignature', s[0:self.signature_length])
        self.setfieldval('StcPadding', s[self.signature_length:(self.signature_length+self.padding_length)])
        self.setfieldval('CustomPattern', s[(self.signature_length+self.padding_length):self.payload_length])
        return s

    def self_build(self, field_pos_list=None):
        ''' Generate the HTTP packet string (the opposite of do_dissect) '''
        p = ""
        for f in self.fields_desc: 
            # Additional fields added for user-friendliness should be ignored
            if f.name not in ['StcSignature', 'StcPadding', 'CustomPattern']:
                continue
            # Get the field value
            val = self.getfieldval(f.name)
            # Add the field into the packet
            p = f.addfield(self, p, val)
        return p

if __name__ == '__main__':
    #p = IP()/TCP()/StcPacket(StcSignature="1234567890"*2, StcPadding="0"*1264, CustomPattern="1"*176)
    p = IP()/TCP()/StcPacket()
    send(p)
    #print hexdump(p)
    ls(p)
    #print p.StcSignature
    #print p.StcPadding
    #print p.CustomPattern