from framework.utils.dispatcher import SimpleEventDispatcher
from framework.ui.console.getch import _Getch
import threading


class KeyPress(threading.Thread):
    def __init__(self):
	threading.Thread.__init__(self)
	self.inkey = _Getch()
	self.setName("KeyPress")

	self.dispatcher = SimpleEventDispatcher()
	self.dispatcher.create_event("?")
	self.dispatcher.create_event("p")
	self.dispatcher.create_event("s")
	self.dispatcher.create_event("q")

	self.do_job = True

    def cancel_job(self):
	self.do_job = False

    def run(self):
	while self.do_job:
	    k = self.inkey()
	    if ord(k) == 3:
		self.dispatcher.notify("q", key="q")
	    elif k == 'p':
		self.dispatcher.notify("p", key="p")
	    elif k == 's':
		self.dispatcher.notify("s", key="s")
	    elif k == '?':
		self.dispatcher.notify("?", key="?")
	    elif k == 'q':
		self.dispatcher.notify("q", key="q")
	#raise KeyboardInterrupt
