from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as of

log = core.getLogger()
import time

swith_dpid_map={"USTC"   : 2352562177,   #0x8c394001
                "CNIC"   : 2352388391,   #0x8c369927
                "IOA"    : 2352858652,   #0x8c3dc61c
                "HUAWEI" : 4103510098,   #0xf4969852
                }

def cooper_loop_ustc(event):
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-1
    temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC2, CNIC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-2
    temp_matchx = core.PofManager.new_matchx(0, '000000000003', 'FFFFFFFFFFFF')   #PC3, USTC
    temp_ins = core.PofManager.new_ins_goto_direct_table(16, 0, 0, 0, None)  #goto MACMAP
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-3
    temp_matchx = core.PofManager.new_matchx(0, 'bc305ba4e124', 'FFFFFFFFFFFF')   #PC3, USTC
    temp_ins = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 1, None)   #EPAT:OUTPUT
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-4
    temp_matchx = core.PofManager.new_matchx(0, '70F3950B7EC7', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-5
    temp_matchx = core.PofManager.new_matchx(0, '643E8C394002', 'FFFFFFFFFFFF')   #USTC SW
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-6
    temp_matchx = core.PofManager.new_matchx(0, 'FFFFFFFFFFFF', 'FFFFFFFFFFFF')   #ARP
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    
    # L2PA (MM) 1-0
    temp_matchx = core.PofManager.new_matchx(2, '0800', 'FFFF')   #IPV4
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 2)
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    # L2PA (MM) 1-1
    temp_matchx = core.PofManager.new_matchx(2, '0806', 'FFFF')   #ARP
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x1003a)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    
    # L3PA (MM) 2-0
    temp_matchx_1 = core.PofManager.new_matchx(7, '11', 'FF')   # Protocol:UDP
    temp_matchx_2 = core.PofManager.new_matchx(12, '12B5', 'FFFF')   # Dport:VxLan
    temp_ins = core.PofManager.new_ins_goto_direct_table(21, 0, 0, 0, None)
    core.PofManager.add_flow_entry(event.dpid, 2, [temp_matchx_1, temp_matchx_2], [temp_ins])
    
    #MACMAP (LINEAR) 16-0
    temp_matchx = core.PofManager.new_matchx(0, 'bc305ba4e124', 'FFFFFFFFFFFF')
    temp_action = core.PofManager.new_action_set_field(temp_matchx)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)   #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 16, [], [temp_ins_1, temp_ins_2])
    
    # VNI (LINEAR) 17-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '72D6A6C1')  # SIP, USTC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '9FE23D4B')  # DIP, CNIC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000032')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '72D6A6C1')  # SIP, USTC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, 'D24BE144')  # DIP, IOA SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000031')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-2
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '72D6A6C1')  # SIP, USTC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '3AFB9F4C')  # DIP, HUAWEI SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000034')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    
    # VxLanEncap (LINEAR) 18-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(128, 16, '0800')  # ETH_TYPE, ipv4
    temp_ins_2 = core.PofManager.new_ins_write_metadata(144, 16, '4500')  # V_IHL_TOS
    temp_ins_3 = core.PofManager.new_ins_write_metadata(208, 16, '4011')  # TTL_PROTOCOL
    temp_ins_4 = core.PofManager.new_ins_write_metadata(320, 16, '12B5')  # UDP_Dport, VxLan
    temp_ins_5 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 1, None)   #goto VxLanEncap-1
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4, temp_ins_5])
    # VxLanEncap (LINEAR) 18-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(304, 16, '04d2')  # UDP_Sport, 1234
    temp_ins_2 = core.PofManager.new_ins_write_metadata(368, 8, '80')  # VxLan Flag
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 2, None)   #goto VxLanEncap-2
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-2
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("UDP_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("Total_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 3, None)   #goto VxLanEncap-3
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    
    # VxLanEncap (LINEAR) 18-3
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("UDP_Len"), 16, None)
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("Total_Len"), 36, None)
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 4, None)   #goto VxLanEncap-4
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-4
    temp_action = core.PofManager.new_action_calculate_checksum(1,1,224,16,144,160)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_table(event.dpid, 8)  # goto FIB
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2])
    
    # FIB (LPM) 8-0
    temp_matchx = core.PofManager.new_matchx(core.PofManager.get_metadata_field("DIP"), "00000000", '00000000')
    temp_ins = core.PofManager.new_ins_goto_direct_table(19, 0, 0, 0, None)  # goto FIB-DT-0
    core.PofManager.add_flow_entry(event.dpid, 8, [temp_matchx], [temp_ins])
    
    # FIB-DT (LINEAR) 19-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(32, 48, '001244662000')  # DMAC, USTC Gateway MAC
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 0, None)  # goto EPAT-0
    core.PofManager.add_flow_entry(event.dpid, 19, [], [temp_ins_1, temp_ins_2])
    
    # EPAT (LINEAR) 20-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(80, 48, '643e8c394002')  # USTC SW MAC
    temp_action = core.PofManager.new_action_output(0, 32, 400, 0, 0x10041)
    temp_ins_2 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1, temp_ins_2])
    # EPAT (LINEAR) 20-1
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x10043)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1])
    
    # VxLanDecap (LINEAR) 21-0
    temp_ins_1 = core.PofManager.new_ins_goto_table(event.dpid, 0, 50)  # goto First
    core.PofManager.add_flow_entry(event.dpid, 21, [], [temp_ins_1])
    
    
def cooper_loop_nc(event):
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-1
    temp_matchx = core.PofManager.new_matchx(0, '000000000002', 'FFFFFFFFFFFF')   #PC2, CNIC
    temp_ins = core.PofManager.new_ins_goto_direct_table(16, 0, 0, 0, None)  #goto MACMAP
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-2
    temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC2, CNIC
    temp_ins = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 1, None)    #EPAT:OUTPUT
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-3
    temp_matchx = core.PofManager.new_matchx(0, 'bc305ba4e124', 'FFFFFFFFFFFF')   #PC3, USTC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)   #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-4
    temp_matchx = core.PofManager.new_matchx(0, '70F3950B7EC7', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-5
    temp_matchx = core.PofManager.new_matchx(0, '643e8c369927', 'FFFFFFFFFFFF')   #NC SW
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-6
    temp_matchx = core.PofManager.new_matchx(0, 'FFFFFFFFFFFF', 'FFFFFFFFFFFF')   #ARP
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    
    # L2PA (MM) 1-0
    temp_matchx = core.PofManager.new_matchx(2, '0800', 'FFFF')   #IPV4
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 2)
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    # L2PA (MM) 1-1
    temp_matchx = core.PofManager.new_matchx(2, '0806', 'FFFF')   #ARP
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x1003a)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    
    # L3PA (MM) 2-0
    temp_matchx_1 = core.PofManager.new_matchx(7, '11', 'FF')   # Protocol:UDP
    temp_matchx_2 = core.PofManager.new_matchx(12, '12B5', 'FFFF')   # Dport:VxLan
    temp_ins = core.PofManager.new_ins_goto_direct_table(21, 0, 0, 0, None)
    core.PofManager.add_flow_entry(event.dpid, 2, [temp_matchx_1, temp_matchx_2], [temp_ins])
    
    #MACMAP (LINEAR) 16-0
    temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   # PC2, CNIC
    temp_action = core.PofManager.new_action_set_field(temp_matchx)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)   #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 16, [], [temp_ins_1, temp_ins_2])
    
    # VNI (LINEAR) 17-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '9FE23D4B')  # SIP, CNIC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, 'D24BE144')  # DIP, IOA SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000021')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '9FE23D4B')  # SIP, CNIC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '72d6a6c1')  # DIP, USTC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000023')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-2
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '9FE23D4B')  # SIP, CNIC SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '3AFB9F4C')  # DIP, HUAWEI SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000024')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    
    # VxLanEncap (LINEAR) 18-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(128, 16, '0800')  # ETH_TYPE, ipv4
    temp_ins_2 = core.PofManager.new_ins_write_metadata(144, 16, '4500')  # V_IHL_TOS
    temp_ins_3 = core.PofManager.new_ins_write_metadata(208, 16, '4011')  # TTL_PROTOCOL
    temp_ins_4 = core.PofManager.new_ins_write_metadata(320, 16, '12B5')  # UDP_Dport, VxLan
    temp_ins_5 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 1, None)   #goto VxLanEncap-1
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4, temp_ins_5])
    # VxLanEncap (LINEAR) 18-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(304, 16, '04d2')  # UDP_Sport, 1234
    temp_ins_2 = core.PofManager.new_ins_write_metadata(368, 8, '80')  # VxLan Flag
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 2, None)   #goto VxLanEncap-2
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-2
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("UDP_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("Total_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 3, None)   #goto VxLanEncap-3
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-3
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("UDP_Len"), 16, None)
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("Total_Len"), 36, None)
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 4, None)   #goto VxLanEncap-4
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-4
    temp_action = core.PofManager.new_action_calculate_checksum(1,1,224,16,144,160)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_table(event.dpid, 8)  # goto FIB
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2])
    
    # FIB (LPM) 8-0
    temp_matchx = core.PofManager.new_matchx(core.PofManager.get_metadata_field("DIP"), "00000000", '00000000')
    temp_ins = core.PofManager.new_ins_goto_direct_table(19, 0, 0, 0, None)  # goto FIB-DT-0
    core.PofManager.add_flow_entry(event.dpid, 8, [temp_matchx], [temp_ins])
    
    # FIB-DT (LINEAR) 19-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(32, 48, '90e2ba2a22cb')  # DMAC, CNIC Gateway MAC
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 0, None)  # goto EPAT-0
    core.PofManager.add_flow_entry(event.dpid, 19, [], [temp_ins_1, temp_ins_2])
    
    # EPAT (LINEAR) 20-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(80, 48, '643e8c369927')  # SMAC, CNIC SW MAC
    temp_action = core.PofManager.new_action_output(0, 32, 400, 0, 0x20000)
    temp_ins_2 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1, temp_ins_2])
    # EPAT (LINEAR) 20-1
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x20002)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1])
    
    # VxLanDecap (LINEAR) 21-0
    temp_ins_1 = core.PofManager.new_ins_goto_table(event.dpid, 0, 50)  # goto First
    core.PofManager.add_flow_entry(event.dpid, 21, [], [temp_ins_1])


def cooper_loop_ioa(event):
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(0, '000000000001', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_ins = core.PofManager.new_ins_goto_direct_table(16, 0, 0, 0, None)    #goto MACMAP
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-1
    temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_ins = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 1, None)  #goto EPAT:OUTPUT
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-2
    temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC2, CNIC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-3
    temp_matchx = core.PofManager.new_matchx(0, 'bc305ba4e124', 'FFFFFFFFFFFF')   #PC3, USTC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-4
    temp_matchx = core.PofManager.new_matchx(0, '70F3950B7EC7', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-5
    temp_matchx = core.PofManager.new_matchx(0, '643e8c3dc61f', 'FFFFFFFFFFFF')   #IOA SW
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-6
    temp_matchx = core.PofManager.new_matchx(0, 'FFFFFFFFFFFF', 'FFFFFFFFFFFF')   #ARP
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    
    # L2PA (MM) 1-0
    temp_matchx = core.PofManager.new_matchx(2, '0800', 'FFFF')   #IPV4
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 2)
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    # L2PA (MM) 1-1
    temp_matchx = core.PofManager.new_matchx(2, '0806', 'FFFF')   #ARP
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x1003a)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    
    # L3PA (MM) 2-0
    temp_matchx_1 = core.PofManager.new_matchx(7, '11', 'FF')   # Protocol:UDP
    temp_matchx_2 = core.PofManager.new_matchx(12, '12B5', 'FFFF')   # Dport:VxLan
    temp_ins = core.PofManager.new_ins_goto_direct_table(21, 0, 0, 0, None)
    core.PofManager.add_flow_entry(event.dpid, 2, [temp_matchx_1, temp_matchx_2], [temp_ins])
    
    #MACMAP (LINEAR) 16-0
    temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   # PC1, IOA
    temp_action = core.PofManager.new_action_set_field(temp_matchx)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)   #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 16, [], [temp_ins_1, temp_ins_2])
    
    # VNI (LINEAR) 17-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, 'D24BE144')  # SIP, IOA SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '9FE23D4B')  # DIP, CNIC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000012')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, 'D24BE144')  # SIP, IOA SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '72d6a6c1')  # DIP, USTC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000013')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-2
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, 'D24BE144')  # SIP, IOA SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '3AFB9F4C')  # DIP, HUAWEI SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000014')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    
    # VxLanEncap (LINEAR) 18-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(128, 16, '0800')  # ETH_TYPE, ipv4
    temp_ins_2 = core.PofManager.new_ins_write_metadata(144, 16, '4500')  # V_IHL_TOS
    temp_ins_3 = core.PofManager.new_ins_write_metadata(208, 16, '4011')  # TTL_PROTOCOL
    temp_ins_4 = core.PofManager.new_ins_write_metadata(320, 16, '12B5')  # UDP_Dport, VxLan
    temp_ins_5 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 1, None)   #goto VxLanEncap-1
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4, temp_ins_5])
    # VxLanEncap (LINEAR) 18-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(304, 16, '04d2')  # UDP_Sport, 1234
    temp_ins_2 = core.PofManager.new_ins_write_metadata(368, 8, '80')  # VxLan Flag
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 2, None)   #goto VxLanEncap-2
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-2
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("UDP_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("Total_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 3, None)   #goto VxLanEncap-3
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-3
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("UDP_Len"), 16, None)
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("Total_Len"), 36, None)
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 4, None)   #goto VxLanEncap-4
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-4
    temp_action = core.PofManager.new_action_calculate_checksum(1,1,224,16,144,160)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_table(event.dpid, 8)  # goto FIB
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2])
    
    # FIB (LPM) 8-0
    temp_matchx = core.PofManager.new_matchx(core.PofManager.get_metadata_field("DIP"), "00000000", '00000000')
    temp_ins = core.PofManager.new_ins_goto_direct_table(19, 0, 0, 0, None)  # goto FIB-DT-0
    core.PofManager.add_flow_entry(event.dpid, 8, [temp_matchx], [temp_ins])
    
    # FIB-DT (LINEAR) 19-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(32, 48, '70f96d594742')  # DMAC, IOA Gateway MAC
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 0, None)  # goto EPAT-0
    core.PofManager.add_flow_entry(event.dpid, 19, [], [temp_ins_1, temp_ins_2])
    
    # EPAT (LINEAR) 20-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(80, 48, '643e8c3dc61f')  # SMAC, IOA SW MAC
    temp_action = core.PofManager.new_action_output(0, 32, 400, 0, 0x10043)
    temp_ins_2 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1, temp_ins_2])
    # EPAT (LINEAR) 20-1
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x10041)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1])
    
    # VxLanDecap (LINEAR) 21-0
    temp_ins_1 = core.PofManager.new_ins_goto_table(event.dpid, 0, 50)  # goto First
    core.PofManager.add_flow_entry(event.dpid, 21, [], [temp_ins_1])
    

def cooper_loop_huawei(event):
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(0, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_ins = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 1, None)  #goto EPAT:OUTPUT
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-1
    temp_matchx = core.PofManager.new_matchx(0, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC2, CNIC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-2
    temp_matchx = core.PofManager.new_matchx(0, 'bc305ba4e124', 'FFFFFFFFFFFF')   #PC3, USTC
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-3
    temp_matchx = core.PofManager.new_matchx(0, '000000000004', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    temp_ins = core.PofManager.new_ins_goto_direct_table(16, 0, 0, 0, None)    #goto MACMAP
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-4
    temp_matchx = core.PofManager.new_matchx(0, '70F3950B7EC7', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    temp_ins = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-5
    temp_matchx = core.PofManager.new_matchx(0, '9C37F4969855', 'FFFFFFFFFFFF')   #IOA SW
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-6
    temp_matchx = core.PofManager.new_matchx(0, 'FFFFFFFFFFFF', 'FFFFFFFFFFFF')   #ARP
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 1)  #goto L2PA
    core.PofManager.add_flow_entry(event.dpid, 0, [temp_matchx], [temp_ins])
    
    # L2PA (MM) 1-0
    temp_matchx = core.PofManager.new_matchx(2, '0800', 'FFFF')   #IPV4
    temp_ins = core.PofManager.new_ins_goto_table(event.dpid, 2)
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    # L2PA (MM) 1-1
    temp_matchx = core.PofManager.new_matchx(2, '0806', 'FFFF')   #ARP
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x1003a)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 1, [temp_matchx], [temp_ins])
    
    # L3PA (MM) 2-0
    temp_matchx_1 = core.PofManager.new_matchx(7, '11', 'FF')   # Protocol:UDP
    temp_matchx_2 = core.PofManager.new_matchx(12, '12B5', 'FFFF')   # Dport:VxLan
    temp_ins = core.PofManager.new_ins_goto_direct_table(21, 0, 0, 0, None)
    core.PofManager.add_flow_entry(event.dpid, 2, [temp_matchx_1, temp_matchx_2], [temp_ins])
    
    #MACMAP (LINEAR) 16-0
    temp_matchx = core.PofManager.new_matchx(0, '70F3950B7EC7', 'FFFFFFFFFFFF')   # PC1, IOA
    temp_action = core.PofManager.new_action_set_field(temp_matchx)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(17, 0, 0, 0, None)   #goto VNI-0
    core.PofManager.add_flow_entry(event.dpid, 16, [], [temp_ins_1, temp_ins_2])
    
    # VNI (LINEAR) 17-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '3AFB9F4C')  # SIP, HUAWEI SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, 'D24BE144')  # DIP, IOA SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000041')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '3AFB9F4C')  # SIP, HUAWEI SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '9FE23D4B')  # DIP, CNIC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000042')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    # VNI (LINEAR) 17-2
    temp_ins_1 = core.PofManager.new_ins_write_metadata(240, 32, '3AFB9F4C')  # SIP, HUAWEI SW
    temp_ins_2 = core.PofManager.new_ins_write_metadata(272, 32, '72d6a6c1')  # DIP, USTC SW
    temp_ins_3 = core.PofManager.new_ins_write_metadata(400, 24, '000043')    # VNI
    temp_ins_4 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 0, None)   #goto VxLanEncap-0
    core.PofManager.add_flow_entry(event.dpid, 17, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4])
    
    # VxLanEncap (LINEAR) 18-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(128, 16, '0800')  # ETH_TYPE, ipv4
    temp_ins_2 = core.PofManager.new_ins_write_metadata(144, 16, '4500')  # V_IHL_TOS
    temp_ins_3 = core.PofManager.new_ins_write_metadata(208, 16, '4011')  # TTL_PROTOCOL
    temp_ins_4 = core.PofManager.new_ins_write_metadata(320, 16, '12B5')  # UDP_Dport, VxLan
    temp_ins_5 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 1, None)   #goto VxLanEncap-1
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3, temp_ins_4, temp_ins_5])
    # VxLanEncap (LINEAR) 18-1
    temp_ins_1 = core.PofManager.new_ins_write_metadata(304, 16, '04d2')  # UDP_Sport, 1234
    temp_ins_2 = core.PofManager.new_ins_write_metadata(368, 8, '80')  # VxLan Flag
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 2, None)   #goto VxLanEncap-2
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-2
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("UDP_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 1, core.PofManager.get_metadata_field("Total_Len"), 0, core.PofManager.get_metadata_field("Pkt_Len"))
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 3, None)   #goto VxLanEncap-3
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-3
    temp_ins_1 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("UDP_Len"), 16, None)
    temp_ins_2 = core.PofManager.new_ins_calculate_field(of.OFPCT_ADD, 0, core.PofManager.get_metadata_field("Total_Len"), 36, None)
    temp_ins_3 = core.PofManager.new_ins_goto_direct_table(18, 0, 0, 4, None)   #goto VxLanEncap-4
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2, temp_ins_3])
    # VxLanEncap (LINEAR) 18-4
    temp_action = core.PofManager.new_action_calculate_checksum(1,1,224,16,144,160)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    temp_ins_2 = core.PofManager.new_ins_goto_table(event.dpid, 8)  # goto FIB
    core.PofManager.add_flow_entry(event.dpid, 18, [], [temp_ins_1, temp_ins_2])
    
    # FIB (LPM) 8-0
    temp_matchx = core.PofManager.new_matchx(core.PofManager.get_metadata_field("DIP"), "00000000", '00000000')
    temp_ins = core.PofManager.new_ins_goto_direct_table(19, 0, 0, 0, None)  # goto FIB-DT-0
    core.PofManager.add_flow_entry(event.dpid, 8, [temp_matchx], [temp_ins])
    
    # FIB-DT (LINEAR) 19-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(32, 48, 'D46AA86BC23F')  # DMAC, HUAWEI Gateway MAC
    temp_ins_2 = core.PofManager.new_ins_goto_direct_table(20, 0, 0, 0, None)  # goto EPAT-0
    core.PofManager.add_flow_entry(event.dpid, 19, [], [temp_ins_1, temp_ins_2])
    
    # EPAT (LINEAR) 20-0
    temp_ins_1 = core.PofManager.new_ins_write_metadata(80, 48, '9C37F4969855')  # SMAC, HUAWEI SW MAC
    temp_action = core.PofManager.new_action_output(0, 32, 400, 0, 0x20003)
    temp_ins_2 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1, temp_ins_2])
    # EPAT (LINEAR) 20-1
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x20001)
    temp_ins_1 = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(event.dpid, 20, [], [temp_ins_1])
    
    # VxLanDecap (LINEAR) 21-0
    temp_ins_1 = core.PofManager.new_ins_goto_table(event.dpid, 0, 50)  # goto First
    core.PofManager.add_flow_entry(event.dpid, 21, [], [temp_ins_1])
    
    
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
            #print "field_id: ", field_id
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
        core.PofManager.add_flow_table(event.dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field(0)])
        core.PofManager.add_flow_table(event.dpid, 'L2PA', of.OF_MM_TABLE, 32,  [core.PofManager.get_field(2)])
        core.PofManager.add_flow_table(event.dpid, 'L3PA', of.OF_MM_TABLE, 32, [core.PofManager.get_field(7),core.PofManager.get_field(12)])
        core.PofManager.add_flow_table(event.dpid, 'FIB', of.OF_LPM_TABLE, 32, [core.PofManager.get_metadata_field("DIP")])
        core.PofManager.add_flow_table(event.dpid, 'MacMap', of.OF_LINEAR_TABLE, 32)   #16
        core.PofManager.add_flow_table(event.dpid, 'VNI', of.OF_LINEAR_TABLE, 32)      #17
        core.PofManager.add_flow_table(event.dpid, 'VxLanEncap', of.OF_LINEAR_TABLE, 32)  #18
        core.PofManager.add_flow_table(event.dpid, 'FIB_DT', of.OF_LINEAR_TABLE, 32)   #19
        core.PofManager.add_flow_table(event.dpid, 'EPAT', of.OF_LINEAR_TABLE, 32)    #20
        core.PofManager.add_flow_table(event.dpid, 'VxLanDncap', of.OF_LINEAR_TABLE, 32)  #21
        
        if event.dpid == swith_dpid_map.get("USTC"):
            cooper_loop_ustc(event)
        """
        if event.dpid == swith_dpid_map.get("CNIC"):
            cooper_loop_nc(event)
        if event.dpid == swith_dpid_map.get("IOA"):
            cooper_loop_ioa(event)
        if event.dpid == swith_dpid_map.get("HUAWEI"):
            cooper_loop_huawei(event)
        """
        
    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        if event.dpid == swith_dpid_map.get("USTC"):
            if port_id == 0x10041 or port_id == 0x10043:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == swith_dpid_map.get("CNIC"):
            if port_id == 0x20000 or port_id == 0x20002:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == swith_dpid_map.get("IOA"):
            if port_id == 0x10041 or port_id == 0x10043:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == swith_dpid_map.get("HUAWEI"):
            if port_id == 0x20001 or port_id == 0x20003:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        
def launch ():
    core.registerNew(TestVxlan)