from pox.core import core
import pox.openflow.libpof_03 as of
#from test.test_support import temp_cwd

ofmatch20_1 = of.ofp_match20(field_name = 'DMAC', field_id = 0, offset = 0, length = 48)
ofmatch20_2 = of.ofp_match20(field_name = 'SMAC', field_id = 1, offset = 48, length = 48)
ofmatch20_3 = of.ofp_match20(field_name = 'ETH_TYPE', field_id = 2, offset = 96, length = 16)

def _handle_ConnectionUp (event):
    ##############################################################################
    #table_mod 0   MM
    ###############################################################################
    msg =of.ofp_table_mod()
    msg.flow_table.match_field_list.append(ofmatch20_1)
    msg.flow_table.command = 0     #OFPTC_ADD
    msg.flow_table.table_id = 0
    msg.flow_table.table_type = 0  #OF_MM_TABLE
    msg.flow_table.match_field_num = 1
    msg.flow_table.table_size = 128
    msg.flow_table.key_length = 48
    msg.flow_table.table_name = "FirstEntryTable"
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #table_mod 1 L2PA
    ###############################################################################
    msg =of.ofp_table_mod()
    msg.flow_table.match_field_list.append(ofmatch20_3)
    msg.flow_table.command=0      #OFPTC_ADD
    msg.flow_table.table_id=1
    msg.flow_table.table_type = 0  #OF_MM_TABLE
    msg.flow_table.match_field_num = 1
    msg.flow_table.table_size = 128
    msg.flow_table.key_length= 16
    msg.flow_table.table_name="L2PA"
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #table_mod 16  MacMap
    ###############################################################################
    msg =of.ofp_table_mod()
    msg.flow_table.command = 0     #OFPTC_ADD
    msg.flow_table.table_id = 0
    msg.flow_table.table_type = 3  #OF_LINEAR_TABLE
    msg.flow_table.table_size = 128
    msg.flow_table.table_name = "MacMap"
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #table_mod 17  VNI
    ###############################################################################
    msg =of.ofp_table_mod()
    msg.flow_table.command = 0 #OFPTC_ADD
    msg.flow_table.table_id = 1
    msg.flow_table.table_type = 3  #OF_LINEAR_TABLE
    msg.flow_table.table_size = 128
    msg.flow_table.table_name = "VNI"
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #flow_mod 0-0  MM
    ###############################################################################
    """
    instruction_goto_table
    """
    msg=of.ofp_flow_mod(table_id = 0, table_type = 0, index = 0, match_field_num = 1, instruction_num = 1)
    temp_matchx = of.ofp_matchx(match20 = ofmatch20_1, value = '90e2ba2a22ca', mask = 'FFFFFFFFFFFF')
    msg.match_list.append(temp_matchx)
    temp_ins = of.ofp_instruction_goto_table(next_table_id = 1, match_field_num = 1, match_list = [ofmatch20_3])
    msg.instruction_list.append(temp_ins)
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #flow_mod 1-0   L2PA
    ###############################################################################
    """
    instruction_write_metadata
    instruction_write_metadata_from_packet
    instruction_goto_direct_table
    """
    msg=of.ofp_flow_mod(table_id = 1, table_type = 0, index = 0, match_field_num = 1, instruction_num = 3)
    temp_matchx = of.ofp_matchx(match20 = ofmatch20_3, value = '0800', mask = 'FFFF')
    msg.match_list.append(temp_matchx)
    temp_ins = of.ofp_instruction_write_metadata(metadata_offset = 32, write_length = 16, value = '0800')
    msg.instruction_list.append(temp_ins)
    temp_ins = of.ofp_instruction_write_metadata_from_packet(metadata_offset = 32, write_length=48, packet_offset = 0)
    msg.instruction_list.append(temp_ins)
    temp_ins = of.ofp_instruction_goto_direct_table(next_table_id = 16, index_type=0, index_value = 0)
    msg.instruction_list.append(temp_ins)
    print msg
    event.connection.send(msg)
    
    ##############################################################################
    #flow_mod 16-0   MacMap
    ###############################################################################
    msg = of.ofp_flow_mod(table_id = 0, table_type = 3, index = 0, instruction_num = 2)
    
    temp_ins=of.ofp_instruction_calculate_field(calc_type = 0, src_value_type = 0, des_field = ofmatch20_3, src_value = 30)  #UDP_length + 30
    msg.instruction_list.append(temp_ins)
    
    temp_ins = of.ofp_instruction_apply_actions(action_num = 4)
    action = of.ofp_action_set_field(field_setting = of.ofp_matchx(match20 = ofmatch20_3, value = '86dd', mask = 'FFFF'))
    temp_ins.action_list.append(action)
    action = of.ofp_action_set_field_from_metadata(field_setting = ofmatch20_3, metadata_offset = 0)
    temp_ins.action_list.append(action)
    action = of.ofp_action_modify_field(match_field = ofmatch20_3, increment = 10)
    temp_ins.action_list.append(action)
    
    
    action = of.ofp_action_output(port_id = 0x10041, metadata_offset = 32, metadata_length = 400)
    temp_ins.action_list.append(action)
    msg.instruction_list.append(temp_ins)
    
    print msg
    event.connection.send(msg)
    
def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)