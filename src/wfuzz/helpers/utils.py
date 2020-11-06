from threading import Lock
import difflib


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


def diff(param1, param2):
    delta = difflib.unified_diff(
        str(param1).splitlines(False),
        str(param2).splitlines(False),
        fromfile="prev",
        tofile="current",
        n=0,
    )

    return "\n".join(delta)
