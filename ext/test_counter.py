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
        table_id = core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field(0)])
        
        # FirstEntryTable (MM) 0-0
        temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC1, IOA
        temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
        core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins])
        # FirstEntryTable (MM) 0-1
        temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC2, CNIC
        temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
        entry_id = core.PofManager.add_flow_entry(event.dpid, table_id, [temp_matchx], [temp_ins])
        
        counter_id = core.PofManager.get_flow_entry(event.dpid, table_id, entry_id).counter_id
        core.PofManager.query_counter_value(event.dpid, counter_id)
        
        
    def _handle_PortStatus(self, event):
        
        port_name = event.ofp.desc.name
        if port_name == "eth1" or port_name == "eth2":
            core.PofManager.set_port_of_enable(event.dpid, core.PofManager.get_port_id_by_name(event.dpid, port_name))
            
    def _handle_CounterReply(self, event):
        print 'test_counter: handle CounterReply'
        
    
def launch ():
    core.registerNew(TestVxlan)