import pox
from pox.core import core
from pox.lib.revent.revent import EventMixin

import Tkinter
import threading

class MyThread(threading.Thread):
    def __init__(self, func, args, name = ''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
    
    def getResult(self):
        return self.res
    
    def run(self):
        self.res = apply(self.func, self.args)


def run_tk():
    root = Tkinter.Tk() # create a root window
    root.mainloop() # create an event loop
    

class TestTk(EventMixin):
    def __init__(self):
        core.openflow.addListeners(self)
        core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)
    
    def _handle_GoingUpEvent (self, event):
        print 'CC: Going up'
        t = MyThread(run_tk,[])
        t.setDaemon(True)
        t.start()
        
def launch():
    core.registerNew(TestTk)