from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of

log = core.getLogger()
import time
"""
def _handle_ConnectionUp (event):
    core.PofManager.set_port_of_enable(event.dpid, core.PofManager.get_port_id_by_name(event.dpid, "eth1"))
    core.PofManager.set_port_of_enable(event.dpid, core.PofManager.get_port_id_by_name(event.dpid, "eth2"))
    
    #ETH
    core.PofManager.new_field("DMAC", 0, 48)    # 0
    #print core.PofManager.get_field(0)               #for test
    #print core.PofManager.get_field("DMAC")          #for test
    core.PofManager.new_field("SMAC", 48, 48)   # 1
    core.PofManager.new_field("Eth_Type", 96,16)  # 2
    #IPV4
    core.PofManager.new_field("V_IHL_TOS", 112, 16)  # 3
    core.PofManager.new_field("Total_Len", 128, 16)  # 4
    core.PofManager.new_field("ID_Flag_Offset", 144, 32)  # 5
    core.PofManager.new_field("TTL", 176, 8)   # 6
    core.PofManager.new_field("Protocol", 184, 8)  # 7
    core.PofManager.new_field("Checksum", 192, 16)  # 8
    core.PofManager.new_field("SIP", 208, 32)  # 9
    core.PofManager.new_field("DIP", 240, 32)  # 10
    #UDP
    core.PofManager.new_field("UDP_Sport", 272, 16)  # 11
    core.PofManager.new_field("UDP_Dport", 288, 16)  # 12
    core.PofManager.new_field("UDP_Len", 304, 16)   #13
    core.PofManager.new_field("UDP_Checksum", 320, 16)  # 14
    
    field_list = core.PofManager.get_all_field()
    print 'protocol_id: ', core.PofManager.add_protocol("ETH_IPV4_UDP", field_list)
    print core.PofManager.get_protocol_by_id(0)
    
    core.PofManager.new_metadata_field("Pkt_Len", 0, 16)
    core.PofManager.new_metadata_field("InPort", 16, 8)
    core.PofManager.new_metadata_field("Rsv", 24, 8)
    
    core.PofManager.new_metadata_field("DMAC", 32, 48)
    core.PofManager.new_metadata_field("SMAC", 80, 48)
    core.PofManager.new_metadata_field("Eth_Type", 128,16)
    core.PofManager.new_metadata_field()
    core.PofManager.new_metadata_field()
    core.PofManager.new_metadata_field()
    core.PofManager.new_metadata_field()
    core.PofManager.new_metadata_field()
    core.PofManager.new_metadata_field()
 
def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
"""
    
class TestVxlan (EventMixin):
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
        
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 128, [core.PofManager.get_field(0)])
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'L2PA', of.OF_MM_TABLE, 128,  [core.PofManager.get_field(2)])
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'L3PA', of.OF_MM_TABLE, 128, [core.PofManager.get_field(7),core.PofManager.get_field(12)])
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'FIB', of.OF_LPM_TABLE, 128, [core.PofManager.get_metadata_field("DIP")])
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'MacMap', of.OF_LINEAR_TABLE, 128)   #16
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'VNI', of.OF_LINEAR_TABLE, 128)      #17
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'VxLanEncap', of.OF_LINEAR_TABLE, 128)  #18
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'FIB_DT', of.OF_LINEAR_TABLE, 128)   #19
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'EPAT', of.OF_LINEAR_TABLE, 128)    #20
        print 'table_id: ',core.PofManager.add_flow_table(event.dpid, 'VxLanDncap', of.OF_LINEAR_TABLE, 128)  #21
        
        # MM 0-0
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='90e2ba2a22ca', mask='FFFFFFFFFFFF')  #PC1
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #VNI
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-1
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='6cf0498cd47b', mask='FFFFFFFFFFFF')  #PC2
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #VNI
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-2
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='000000000003', mask='FFFFFFFFFFFF')  #PC3
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=16, index_value=0)   #MACMAP
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-3
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='bc305ba4e124', mask='FFFFFFFFFFFF')  #PC3
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=19, index_value=1)   #goto EPAT:OUTPUT
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-4
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='70F3950B7EC7', mask='FFFFFFFFFFFF')  #PC4
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #goto VNI
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-5
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value='643E8C394002', mask='FFFFFFFFFFFF')  #USTC SW
        temp_ins = of.ofp_instruction_goto_table(next_table_id=1, match_field_num = 1, match_list = [core.PofManager.get_field(2)])  #goto L2PA
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        # MM 0-6
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(0), value="FFFFFFFFFFFF", mask='FFFFFFFFFFFF')  #ARP
        temp_ins = of.ofp_instruction_goto_table(next_table_id=1, match_field_num = 1, match_list = [core.PofManager.get_field(2)])  #goto L2PA
        entry_id = core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
        
        # L2PA (MM) 1-0
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(2), value="0800", mask='FFFF')  #IPV4
        temp_ins = of.ofp_instruction_goto_table(next_table_id=2, match_field_num=2, match_list=[core.PofManager.get_field(7),core.PofManager.get_field(12)])  #goto L3PA
        entry_id = core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
        # L2PA (MM) 1-1
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_field(2), value="0806", mask='FFFF')  #ARP
        temp_ins = of.ofp_instruction_apply_actions(action_num = 1)
        action = of.ofp_action_output(port_id = 0x1003a)
        temp_ins.action_list.append(action)
        entry_id = core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
        
        # L3PA (MM) 2-0
        temp_matchx_1 = of.ofp_matchx(match20=core.PofManager.get_field(7), value="11", mask='FF')  #ARP
        temp_matchx_2 = of.ofp_matchx(match20=core.PofManager.get_field(12), value="12B5", mask='FFFF')  #ARP
        temp_ins_1 = of.ofp_instruction_goto_direct_table(next_table_id=21, index_value=0)   #goto VxLanDecap
        entry_id = core.PofManager.add_flow_entry(event.dpid, 2, [temp_matchx_1, temp_matchx_2], [temp_ins_1])
        
        #MACMAP (LINEAR) 16-0
        temp_ins_1 = of.ofp_instruction_apply_actions(action_num = 1)
        action = of.ofp_action_set_field(field_setting = of.ofp_matchx(match20 = core.PofManager.get_field(0), value = 'bc305ba4e124', mask = 'FFFFFFFFFFFF'))
        temp_ins_1.action_list.append(action)
        temp_ins_2 = of.ofp_instruction_goto_direct_table(next_table_id=17, index_value=0)   #goto VNI
        entry_id = core.PofManager.add_flow_entry(event.dpid, 16, [], [temp_ins_1, temp_ins_2])
        
        # VNI (LINEAR) 17-0
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 240, write_length = 32, value = '72D6A6C1')  # SIP, USTC SW
        temp_ins_2 = of.ofp_instruction_write_metadata(metadata_offset = 272, write_length = 32, value = '9FE23D4B')  # DIP, NC SW
        temp_ins_3 = of.ofp_instruction_write_metadata(metadata_offset = 400, write_length = 24, value = '000032')    # VNI
        temp_ins_4 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=0)  #goto VxLanEncap
        entry_id = core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
        # VNI (LINEAR) 17-1
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 240, write_length = 32, value = '72D6A6C1')  # SIP, USTC SW
        temp_ins_2 = of.ofp_instruction_write_metadata(metadata_offset = 272, write_length = 32, value = 'D24BE144')  # DIP, IOA SW
        temp_ins_3 = of.ofp_instruction_write_metadata(metadata_offset = 400, write_length = 24, value = '000031')    # VNI
        temp_ins_4 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=0)  #goto VxLanEncap
        entry_id = core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
        # VNI (LINEAR) 17-2
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 240, write_length = 32, value = '72D6A6C1')  # SIP, USTC SW
        temp_ins_2 = of.ofp_instruction_write_metadata(metadata_offset = 272, write_length = 32, value = '3AFB9F4C')  # DIP, HUAWEI SW
        temp_ins_3 = of.ofp_instruction_write_metadata(metadata_offset = 400, write_length = 24, value = '000034')    # VNI
        temp_ins_4 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=0)  #goto VxLanEncap-0
        entry_id = core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
        
        # VxLanEncap (LINEAR) 18-0
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 128, write_length = 16, value = '0800')  # ETH_TYPE, ipv4
        temp_ins_2 = of.ofp_instruction_write_metadata(metadata_offset = 144, write_length = 16, value = '4500')  # V_IHL_TOS
        temp_ins_3 = of.ofp_instruction_write_metadata(metadata_offset = 208, write_length = 16, value = '4011')  # TTL_PROTOCOL
        temp_ins_4 = of.ofp_instruction_write_metadata(metadata_offset = 320, write_length = 16, value = '12B5')  # UDP_Dport, VxLan
        temp_ins_5 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=1)  #goto VxLanEncap-1
        entry_id = core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4, temp_ins_5])
        # VxLanEncap (LINEAR) 18-1
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 304, write_length = 16, value = '04d2')  # UDP_Sport, 1234
        temp_ins_2 = of.ofp_instruction_write_metadata(metadata_offset = 368, write_length = 8, value = '80')  # VxLan Flag
        temp_ins_3 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=2)  #goto VxLanEncap-2
        entry_id = core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
        # VxLanEncap (LINEAR) 18-2
        temp_ins_1=of.ofp_instruction_calculate_field(calc_type=of.OFPCT_ADD, src_value_type=1, src_field=core.PofManager.get_metadata_field("Pkt_Len"), des_field=core.PofManager.get_metadata_field("UDP_Len"))
        temp_ins_2=of.ofp_instruction_calculate_field(calc_type=of.OFPCT_ADD, src_value_type=1, src_field=core.PofManager.get_metadata_field("Pkt_Len"), des_field=core.PofManager.get_metadata_field("Total_Len"))
        temp_ins_3 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=3)  #goto VxLanEncap-3
        entry_id = core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
        # VxLanEncap (LINEAR) 18-3
        temp_ins_1=of.ofp_instruction_calculate_field(calc_type=of.OFPCT_ADD, src_value_type=0, src_value=16, des_field=core.PofManager.get_metadata_field("UDP_Len"))
        temp_ins_2=of.ofp_instruction_calculate_field(calc_type=of.OFPCT_ADD, src_value_type=0, src_value=36, des_field=core.PofManager.get_metadata_field("Total_Len"))
        temp_ins_3 = of.ofp_instruction_goto_direct_table(next_table_id=18, index_value=4)  #goto VxLanEncap-4
        entry_id = core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
        # VxLanEncap (LINEAR) 18-4
        temp_ins_1 = of.ofp_instruction_apply_actions(action_num = 1)
        action=of.ofp_action_calculate_checksum(checksum_pos_type=1, calc_pos_type=1, checksum_position=224,checksum_length=16,calc_start_position=144,calc_length=160)
        temp_ins_1.action_list.append(action)
        temp_ins_2 = of.ofp_instruction_goto_table(next_table_id=8, match_field_num = 1, match_list = [core.PofManager.get_metadata_field("DIP")])
        entry_id = core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2])
        #print 'entry_id: ', entry_id
        
        # FIB (LPM) 8-0
        temp_matchx = of.ofp_matchx(match20=core.PofManager.get_metadata_field("DIP"), value="00000000", mask='00000000') 
        temp_ins = of.ofp_instruction_goto_direct_table(next_table_id=19, index_value=0)    # goto FIB-DT
        entry_id = core.PofManager.add_flow_entry(event.dpid, 8, [temp_matchx], [temp_ins])
        
        # FIB-DT (LINEAR) 19-0
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 32, write_length = 48, value = '001244662000')  # DMAC, USTC Gateway MAC
        temp_ins_2 = of.ofp_instruction_goto_direct_table(next_table_id=20, index_value=0)    # goto EPAT
        entry_id = core.PofManager.add_flow_entry(event.dpid, 19, [], [temp_ins_1, temp_ins_2])
        
        # EPAT (LINEAR) 20-0
        temp_ins_1 = of.ofp_instruction_write_metadata(metadata_offset = 80, write_length = 48, value = '643e8c394002')  # USTC SW MAC
        temp_ins_2 = of.ofp_instruction_apply_actions(action_num = 1)
        action = of.ofp_action_output(port_id = 0x10041, metadata_offset = 32, metadata_length = 400)
        temp_ins_2.action_list.append(action)
        entry_id = core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1, temp_ins_2])
        # EPAT (LINEAR) 20-1
        temp_ins_1 = of.ofp_instruction_apply_actions(action_num = 1)
        action = of.ofp_action_output(port_id = 0x10043)
        temp_ins_1.action_list.append(action)
        entry_id = core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1])
        
        # VxLanDecap (LINEAR) 21-0
        temp_ins_1 = of.ofp_instruction_goto_table(next_table_id=0, match_field_num=1, packet_offset=50, match_list = [core.PofManager.get_field(0)])
        entry_id = core.PofManager.add_flow_entry(event.dpid, 21, [], [temp_ins_1])
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
    
def launch ():
    core.registerNew(TestVxlan)