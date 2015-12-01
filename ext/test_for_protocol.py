from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of
from pox.web.webcore import CoreHandler

log = core.getLogger()
import time

    
class TestVxlan (EventMixin):
    def __init__ (self):
        # Listen to dependencies
        self.add_protocol()
        self.add_metadata()
        core.openflow.addListeners(self, priority=0)
        
    def add_protocol(self):
        field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                      ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32),
                      ("UDP_Sport",16), ("UDP_Dport",16), ("UDP_Len",16), ("UDP_Checksum",16)]
        match_field_list = []
        total_offset = 0
        for field in field_list:
            field_id = core.PofManager.new_field(field[0], total_offset, field[1])
            print "field_id: ", field_id
            total_offset += field[1]
            match_field_list.append(core.PofManager.get_field(field_id))
        print 'protocol_id: ', core.PofManager.add_protocol("ETH_IPV4_UDP", match_field_list)
        
        protocol = core.PofManager.get_protocol_by_id(0)
        print '123123',protocol.protocol_id
        print '123123',protocol.protocol_name
        
        
    def add_metadata(self):
        metadata_list = [("Pkt_Len",16),("InPort",8),("Rsv",8),("DMAC",48),("SMAC",48),("Eth_Type",16),
                         ("V_IHL_TOS",16),("Total_Len",16),("ID_Flag_Offset",32),("TTL",8),("Protocol",8),("Checksum",16),
                         ("SIP",32),("DIP",32),("UDP_Sport",16),("UDP_Dport",16),("UDP_Len",16),("UDP_Checksum",16),
                         ("VxLan_Flag",8),("VxLan_Rsv_1",24),("VxLan_VNI",24),("VxLan_Rsv_2",8)]
        #metadata_field_list = []
        total_offset = 0
        for field in metadata_list:
            core.PofManager.new_metadata_field(field[0], total_offset, field[1])
            total_offset += field[1]
        
    def _handle_ConnectionUp (self, event):
        core.PofManager.del_protocol(0)
        pass
        
    def _handle_PortStatus(self, event):
        pass
        
    
def launch ():
    core.registerNew(TestVxlan)