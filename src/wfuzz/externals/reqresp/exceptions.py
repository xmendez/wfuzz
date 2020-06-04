class ReqRespException(Exception):
    FATAL, RESOLVE_PROXY, RESOLVE_HOST, CONNECT_HOST, SSL, TIMEOUT = list(range(6))

    def __init__(self, etype, msg):
        self.etype = etype
        self.msg = msg
        Exception.__init__(self, msg)
