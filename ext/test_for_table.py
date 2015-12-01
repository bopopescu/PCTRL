from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of

log = core.getLogger()
import time

    
class TestTable (EventMixin):
    def __init__ (self):
        # Listen to dependencies
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
        #core.PofManager.set_port_of_enable(event.dpid, core.PofManager.get_port_id_by_name(event.dpid, "eth1"))
        #core.PofManager.set_port_of_enable(event.dpid, core.PofManager.get_port_id_by_name(event.dpid, "eth2"))
         
        self.add_protocol()
        self.add_metadata()
        
        table_id = core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 128, [core.PofManager.get_field(0)])
        print 'table_id: ', table_id
        print core.PofManager.get_all_flow_table(event.dpid)
        #core.PofManager.del_empty_flow_table(event.dpid, table_id)
        
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='90e2ba2a22ca', mask='FFFFFFFFFFFF')  #PC1
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #VNI
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        print 'entry_id', entry_id
        
        #print core.PofManager.get_all_flow_entry(event.dpid, table_id)
        #print core.PofManager.get_flow_entry(event.dpid, table_id, entry_id)
        
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='6cf0498cd47b', mask='FFFFFFFFFFFF')  #PC2
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #VNI
        core.PofManager.modify_flow_entry(event.dpid, entry_id, 0, [temp_matchx], [temp_ins])
        
        print core.PofManager.get_all_flow_entry(event.dpid, table_id)
        print core.PofManager.get_flow_entry(event.dpid, table_id, entry_id)
        
        core.PofManager.del_flow_table_and_all_sub_entries(event.dpid, table_id)
        core.PofManager.del_all_flow_tables(event.dpid)
        print core.PofManager.get_all_flow_table(event.dpid)
        
        
def launch ():
    core.registerNew(TestTable)