__title__ = "wfuzz"
__version__ = "3.0.0"
__build__ = 0x023000
__author__ = "Xavier Mendez"
__license__ = "GPL 2.0"
__copyright__ = "Copyright 2011-2018 Xavier Mendez"

import logging
import sys

import warnings


# define a logging Handler
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter("%(name)-12s: %(levelname)-8s %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)


# define warnings format
def warning_on_one_line(message, category, filename, lineno, file=None, line=None):
    return " %s:%s: %s:%s\n" % (filename, lineno, category.__name__, message)


warnings.formatwarning = warning_on_one_line


try:
    import pycurl

    if "openssl".lower() not in pycurl.version.lower():
        warnings.warn(
            "Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information."
        )

    if not hasattr(pycurl, "CONNECT_TO"):
        warnings.warn(
            "Pycurl and/or libcurl version is old. CONNECT_TO option is missing. Wfuzz --ip option will not be available."
        )

    if not hasattr(pycurl, "PATH_AS_IS"):
        warnings.warn(
            "Pycurl and/or libcurl version is old. PATH_AS_IS option is missing. Wfuzz might not correctly fuzz URLS with '..'."
        )

except ImportError:
    warnings.warn(
        "fuzz needs pycurl to run. Pycurl could be installed using the following command: $ pip install pycurl"
    )

    sys.exit(1)

from .options import FuzzSession
from .api import fuzz, get_payload, get_payloads, encode, decode, payload, get_session
