
'''
Created on Oct 2, 2018

@author: zevloy
'''

#from scapy.all import *
from config import init_conf, get_stcPacket_conf
from trex_stl_lib.api import *


class STC(Packet):
    """define a sprirent test center kind of Packet Layer Class"""

    name = "STC"

    #init_conf("StcConf/case91_p1_tx_traffic_config.xml")
    custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length = get_stcPacket_conf()
    fields_desc = [StrField("sig", '0'*signature_length, fmt="H"), StrField("padding", '0'*padding_length, fmt="H"), StrField("customPattern", '1'*custom_pattern_length, fmt="H")]
    #fields_desc = [StrLenField("sig", "", "len"), StrLenField("padding", "", "len"), StrLenField("custom_pattern", "1", "len")]

    def guess_payload_class(self, payload):
        ''' Decides if the payload contain the Custom pattern'''
        if payload.endswith(self.custom_pattern):
            return STC
        else:
            return Packet.guess_payload_class(self, payload)

    def do_dissect(self, s):
        ''' From the STC packet layer string, populate the scapy object '''

        self.setfieldval('sig', s[0:self.signature_length])
        self.setfieldval('padding', s[self.signature_length:(self.signature_length+self.padding_length)])
        self.setfieldval('customPattern', s[(self.signature_length+self.padding_length):self.payload_length])
        return s

    def self_build(self, field_pos_list=None):
        ''' Generate the stc packet string (the opposite of do_dissect) '''
        p = ""
        for f in self.fields_desc:
            # Additional fields added for user-friendliness should be ignored
            if f.name not in ['sig', 'padding', 'customPattern']:
                continue
            # Get the field value
            val = self.getfieldval(f.name)
            # Add the field into the packet
            p = f.addfield(self, p, val)
        return p

if __name__ == '__main__':

    custom_pattern, signature_length, payload_length, custom_pattern_length, padding_length = get_stcPacket_conf()
    #p5 = STC(sig="1"*signature_length, padding="0"*padding_length, custom_pattern="1"*custom_pattern_length)
    p5 = STC()
    p = IP()/TCP()/p5
    send(p)
    #print hexdump(p)
    ls(p5)
    #print p.StcSignature
    #print p.StcPadding
    #print p.CustomPattern
    print STC.__dict__
    #print p5.fields_desc[0].length_from
    #a = StrLenField("sig", "", "len")

