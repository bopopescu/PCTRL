"""
Configure by shell
"""
from pox.core import core
import pox.openflow.libpof_02 as of

DEVICE_ID = 2215152430

device_map = {"USTC": 2215152430,
              }


def add_protocol():
    """
    Define a new protocol, and save it to PMDatabase.
    field_list:[("field_name", length)]
    """
    field_list = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                  ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32),
                  ("UDP_Sport",16), ("UDP_Dport",16), ("UDP_Len",16), ("UDP_Checksum",16)]
    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])   #field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("ETH_IPV4_UDP", match_field_list)
    
    
def add_metadata():
    """
    Define the metadata, and save it to PMDatabase.
    field_list:[("field_name", length)]
    """
    metadata_list = [("Pkt_Len",16),("InPort",8),("Rsv",8),("DMAC",48),("SMAC",48),("Eth_Type",16),
                     ("V_IHL_TOS",16),("Total_Len",16),("ID_Flag_Offset",32),("TTL",8),("Protocol",8),("Checksum",16),
                     ("SIP",32),("DIP",32),("UDP_Sport",16),("UDP_Dport",16),("UDP_Len",16),("UDP_Checksum",16),
                     ("VxLan_Flag",8),("VxLan_Rsv_1",24),("VxLan_VNI",24),("VxLan_Rsv_2",8)]
    total_offset = 0
    for field in metadata_list:
        core.PofManager.new_metadata_field(field[0], total_offset, field[1])
        total_offset += field[1]


def set_port():
    core.PofManager.set_port_of_enable(DEVICE_ID, core.PofManager.get_port_id_by_name(DEVICE_ID, "eth1"))
    core.PofManager.set_port_of_enable(DEVICE_ID, core.PofManager.get_port_id_by_name(DEVICE_ID, "eth2"))
    

def add_table_vxlan(device_id):
    core.PofManager.add_flow_table(device_id, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field("DMAC")[0]])
    core.PofManager.add_flow_table(device_id, 'L2PA', of.OF_MM_TABLE, 32,  [core.PofManager.get_field("Eth_Type")[0]])
    core.PofManager.add_flow_table(device_id, 'L3PA', of.OF_MM_TABLE, 32, [core.PofManager.get_field("Protocol")[0],core.PofManager.get_field("UDP_Dport")[0]])
    core.PofManager.add_flow_table(device_id, 'FIB', of.OF_LPM_TABLE, 32, [core.PofManager.get_metadata_field("DIP")])
    core.PofManager.add_flow_table(device_id, 'MacMap', of.OF_LINEAR_TABLE, 32)   #16
    core.PofManager.add_flow_table(device_id, 'VNI', of.OF_LINEAR_TABLE, 32)      #17
    core.PofManager.add_flow_table(device_id, 'VxLanEncap', of.OF_LINEAR_TABLE, 32)  #18
    core.PofManager.add_flow_table(device_id, 'FIB_DT', of.OF_LINEAR_TABLE, 32)   #19
    core.PofManager.add_flow_table(device_id, 'EPAT', of.OF_LINEAR_TABLE, 32)    #20
    core.PofManager.add_flow_table(device_id, 'VxLanDncap', of.OF_LINEAR_TABLE, 32)  #21


def add_entry_vxlan(device_id):
    # FirstEntryTable (MM) 0
    table_id = core.PofManager.get_flow_table_id(device_id, 'FirstEntryTable')
    match = core.PofManager.get_field("DMAC")[0]
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(match, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'VNI')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-1
    temp_matchx = core.PofManager.new_matchx(match, '90e2ba2a22ca', 'FFFFFFFFFFFF')   #PC2, CNIC
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'VNI')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-2
    temp_matchx = core.PofManager.new_matchx(match, '000000000003', 'FFFFFFFFFFFF')   #PC3, USTC
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'MacMap')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)  #goto MACMAP
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-3
    temp_matchx = core.PofManager.new_matchx(match, 'bc305ba4e124', 'FFFFFFFFFFFF')   #PC3, USTC
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'EPAT')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 1, None)   #goto EPAT:OUTPUT
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-4
    temp_matchx = core.PofManager.new_matchx(match, '70F3950B7EC7', 'FFFFFFFFFFFF')   #PC4, HUAWEI
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'VNI')
    temp_ins = core.PofManager.new_ins_goto_direct_table(next_table_id, 0, 0, 0, None)    #goto VNI-0
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-5
    temp_matchx = core.PofManager.new_matchx(match, '643E8C394002', 'FFFFFFFFFFFF')   #USTC SW
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'L2PA')
    temp_ins = core.PofManager.new_ins_goto_table(device_id, next_table_id)           #goto L2PA
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # FirstEntryTable (MM) 0-6
    temp_matchx = core.PofManager.new_matchx(match, 'FFFFFFFFFFFF', 'FFFFFFFFFFFF')   #ARP
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'L2PA')
    temp_ins = core.PofManager.new_ins_goto_table(device_id, next_table_id)            #goto L2PA
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    
    
    # L2PA (MM) 1
    table_id = core.PofManager.get_flow_table_id(device_id, 'L2PA')
    match = core.PofManager.get_field("Eth_Type")[0]
    # L2PA (MM) 1-0
    temp_matchx = core.PofManager.new_matchx(match, '0800', 'FFFF')   #IPV4
    next_table_id = core.PofManager.get_flow_table_id(device_id, 'L3PA')
    temp_ins = core.PofManager.new_ins_goto_table(device_id, next_table_id)
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    # L2PA (MM) 1-1
    temp_matchx = core.PofManager.new_matchx(match, '0806', 'FFFF')   #ARP
    temp_action = core.PofManager.new_action_output(0, 0, 0, 0, 0x1003a)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    

def launch():
    add_protocol()
    add_metadata()
    #set_port()
    add_table_vxlan(DEVICE_ID)
    add_entry_vxlan(DEVICE_ID)
    
    