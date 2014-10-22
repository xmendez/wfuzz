
class FuzzException(Exception):
    FATAL, SIGCANCEL = range(2)

    def __init__(self, etype, msg):
	self.etype = etype
	self.msg = msg
        Exception.__init__(self, msg)
