from threading import Lock


class MyCounter:
    def __init__(self, count=0):
        self._count = count
        self._mutex = Lock()

    def inc(self):
        return self._operation(1)

    def dec(self):
        return self._operation(-1)

    def _operation(self, dec):
        with self._mutex:
            self._count += dec
            return self._count

    def __call__(self):
        with self._mutex:
            return self._count
