'''
Created on Nov 4, 2014

@author: cc
'''
from pox.lib.revent.revent import EventMixin
from pox.core import core
import pox.openflow.libpof_01 as pof

class TestCounterMod(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self)
        
    def _handle_ConnectionUp(self, event):
        msg = pof.ofp_counter_mod()
        msg.counter.command = pof.OFPCC_ADD    #0
        msg.counter.counter_id = 1
        event.connection.send(msg)
        
        msg = pof.ofp_counter_request()
        msg.counter.command = pof.OFPCC_QUERY   #3
        msg.counter.counter_id = 1
        event.connection.send(msg)
        
def launch ():
    core.registerNew(TestCounterMod)
        