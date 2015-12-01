'''
Created on Nov 5, 2014

@author: cc
'''

from pox.lib.revent.revent import EventMixin
from pox.core import core
import pox.openflow.libpof_02 as pof

class TestPortMod(EventMixin):
    
    def __init__(self):
        core.openflow.addListeners(self)
        
    def _handle_PortStatus(self, event):
        # add port (except eth0) to the switch
        msg = pof.ofp_port_mod()
        msg.desc = event.ofp.desc
        msg.desc.of_enable = 1       # pof enable
        
        if msg.desc.name == 'eth2':
            #print "CC: send PORT_MOD message\n",msg
            event.connection.send(msg)
        
        
def launch ():
    core.registerNew(TestPortMod)