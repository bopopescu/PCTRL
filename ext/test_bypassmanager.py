'''
Created on Nov 4, 2014

@author: CC
'''
from pox.core import core
from pox.lib.revent.revent import EventMixin

class TestByPassManager(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        
    def _handle_FeaturesReceived(self, event):
        print "test_bypassmanager -----> handle FeaturesReceived event"
        #print event.ofp
        
    def _handle_PortStatus(self, event):
        print "test_bypassmanager -----> handle PortStatus event"
        #print event.ofp
    
    def _handle_ResourceReport(self, event):
        print "test_bypassmanager -----> handle ResourceReport event"
        #print event.ofp
        
    def _handle_ErrorIn(self, event):
        print "test_bypassmanager -----> handle ErrorIn event"

def launch():
    core.registerNew(TestByPassManager)