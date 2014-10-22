from collections import defaultdict

class SimpleEventDispatcher:
    def __init__(self):
	self.publisher = defaultdict(list)

    def create_event(self, msg):
	self.publisher[msg] = []

    def subscribe(self, func, msg, dynamic = False):
	if not self.publisher.has_key(msg) and not dynamic:
	    raise KeyError, 'subscribe. No such event: %s' % (msg)
	else:
	    self.publisher[msg].append(func)

    def notify(self, msg, **event):
	if not self.publisher.has_key(msg):
	    raise KeyError, 'notify. Event not subscribed: %s' % (msg,)
	else:
	    for functor in self.publisher[msg]:
		functor(**event)


