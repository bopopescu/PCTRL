'''
Created on 2015.07.09

@author: Cen
'''

from pox.core import core
import pox.openflow.libpof_02 as of
from pox.lib.revent.revent import EventMixin

device_map = { # HUAWEI switch
              "USTC"   : 2352562177,
              "CNIC"   : 2352388391,
              "IOA"    : 2352858652,
              "HUAWEI" : 4103510098,
              "IIE"    : 1055891609,
              }

def _add_protocol(protocol_name, field_list):
    """
    Define a new protocol, and save it to PMDatabase.
    
    protocol_name: string
    field_list:[("field_name", length)]
    """
    match_field_list = []
    total_offset = 0
    for field in field_list:
        field_id = core.PofManager.new_field(field[0], total_offset, field[1])   #field[0]:field_name, field[1]:length
        total_offset += field[1]
        match_field_list.append(core.PofManager.get_field(field_id))
    core.PofManager.add_protocol("protocol_name", match_field_list)
    
def add_protocol():   # TODO: add 10 different protocol
    field_list_0 = [("DMAC",48), ("SMAC",48), ("Eth_Type",16), ("V_IHL_TOS",16), ("Total_Len",16),
                  ("ID_Flag_Offset",32), ("TTL",8), ("Protocol",8), ("Checksum",16), ("SIP",32), ("DIP",32),
                  ("UDP_Sport",16), ("UDP_Dport",16), ("UDP_Len",16), ("UDP_Checksum",16)]
    _add_protocol("ETH_IPV4_UDP", field_list_0)
    
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
        
def add_table(device_id):
    core.PofManager.add_flow_table(device_id, 'FirstEntryTable', of.OF_MM_TABLE, 32, [core.PofManager.get_field("DMAC")[0]])
    core.PofManager.add_flow_table(device_id, 'L2PA', of.OF_MM_TABLE, 32,  [core.PofManager.get_field("Eth_Type")[0]])
    core.PofManager.add_flow_table(device_id, 'L3PA', of.OF_MM_TABLE, 32, [core.PofManager.get_field("Protocol")[0],core.PofManager.get_field("UDP_Dport")[0]])
    core.PofManager.add_flow_table(device_id, 'FIB', of.OF_LPM_TABLE, 32, [core.PofManager.get_metadata_field("DIP")])
    core.PofManager.add_flow_table(device_id, 'MacMap', of.OF_LINEAR_TABLE, 32)   #16
    core.PofManager.add_flow_table(device_id, 'VNI', of.OF_LINEAR_TABLE, 32)      #17
    core.PofManager.add_flow_table(device_id, 'VxLanEncap', of.OF_LINEAR_TABLE, 32)  #18
    core.PofManager.add_flow_table(device_id, 'FIB_DT', of.OF_LINEAR_TABLE, 32)   #19
    core.PofManager.add_flow_table(device_id, 'EPAT', of.OF_LINEAR_TABLE, 32)    #20
    core.PofManager.add_flow_table(device_id, 'VxLanDecap', of.OF_LINEAR_TABLE, 32)  #21    
        
def add_entry_ustc():
    device_id = device_map["USTC"]
    #device_id = DEVICE_ID
    
    # FirstEntryTable (MM) 0
    table_id = core.PofManager.get_flow_table_id(device_id, 'FirstEntryTable')
    match = core.PofManager.get_field("DMAC")[0]
    # FirstEntryTable (MM) 0-0
    temp_matchx = core.PofManager.new_matchx(match, '6cf0498cd47b', 'FFFFFFFFFFFF')   #PC1, IOA
    temp_action = core.PofManager.new_action_packetin(1)
    temp_ins = core.PofManager.new_ins_apply_actions([temp_action])
    core.PofManager.add_flow_entry(device_id, table_id, [temp_matchx], [temp_ins])
    
    
class Test(EventMixin):
    def __init__ (self):
        add_protocol()
        add_metadata()
        core.openflow.addListeners(self, priority=0)   # Listen to dependencies
            
    def _handle_ConnectionUp (self, event):
        if event.dpid == device_map.get("USTC"):
            add_table(event.dpid)           # add table
            add_entry_ustc()
        
    def _handle_PortStatus(self, event):
        port_id = event.ofp.desc.port_id
        if event.dpid == device_map.get("USTC"):
            if port_id == 0x10041 or port_id == 0x10045:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == device_map.get("CNIC"):
            if port_id == 0x20000 or port_id == 0x20002:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == device_map.get("IOA"):
            if port_id == 0x10041 or port_id == 0x10043:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == device_map.get("HUAWEI"):
            if port_id == 0x20001 or port_id == 0x20003:
                core.PofManager.set_port_of_enable(event.dpid, port_id)
        if event.dpid == device_map.get("IIE"):
            if port_id == 0x20001 or port_id == 0x20003:
                core.PofManager.set_port_of_enable(event.dpid, port_id)  

    def _handle_PacketIn(self, event):
        print "yes, its the handle packetin fuction"

def counter(sw_name, global_table_id, entry_id):   #sw_name:string
    device_id = device_map[sw_name]
    counter_id = core.PofManager.get_flow_entry(device_id, global_table_id, entry_id).counter_id
    core.PofManager.query_counter_value(device_id, counter_id)

def launch ():
    core.registerNew(Test)
    