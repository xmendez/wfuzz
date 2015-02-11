
class FuzzException(Exception):
    FATAL, SIGCANCEL, SIG_ENDSEED = range(3)

    def __init__(self, etype, msg):
	self.etype = etype
	self.msg = msg
        Exception.__init__(self, msg)
