'''
Created on Nov 5, 2014

@author: cc
'''
from pox.core import core
from pox.lib.revent.revent import EventMixin
import pox.openflow.libpof_02 as pof

class TestTableMod(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self)
        
    def _handle_ConnectionUp(self, event):
        msg = pof.ofp_table_mod()
        match = pof.ofp_match20(field_id = 1, offset  = 0, length = 48)
        #match.field_id = 1
        #match.offset = 0
        #match.length = 48
        msg.flow_table.match_field_list.append(match)
        msg.flow_table.match_field_num = 1
        msg.flow_table.table_size = 128
        msg.flow_table.key_length = 48
        msg.flow_table.table_name = 'FirstEntryTable'
        
        print 'send TABLE_MOD message:\n', msg
           
        event.connection.send(msg)
        """
        msg = pof.ofp_flow_mod()
        msg.priority = 0
        matchx = pof.ofp_matchx()
        matchx.field_id = 2
        matchx.offset = 48
        matchx.length = 48
        msg.matchList.append(matchx)
        msg.matchFieldNum = 1
        
        instruction = pof.ofp_instruction()
        instruction.type = 6
        instruction.length = 16
        msg.instruction.append(instruction)
        msg.instructionNum = 1
                    
        event.connection.send(msg)
        """
def launch():
    core.registerNew(TestTableMod)