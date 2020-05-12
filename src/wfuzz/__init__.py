__title__ = 'wfuzz'
__version__ = "3.0.0"
__build__ = 0x023000
__author__ = 'Xavier Mendez'
__license__ = 'GPL 2.0'
__copyright__ = 'Copyright 2011-2018 Xavier Mendez'

import logging
import sys

from .helpers.utils import eprint


# define a logging Handler
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


try:
    import pycurl

    if "openssl".lower() not in pycurl.version.lower():
        eprint("\nWarning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.\n")

    if not hasattr(pycurl, "CONNECT_TO"):
        eprint("\nWarning: Pycurl and/or libcurl version is old. CONNECT_TO option is missing. Wfuzz --ip option will not be available.\n")

    if not hasattr(pycurl, "PATH_AS_IS"):
        eprint("\nWarning: Pycurl and/or libcurl version is old. PATH_AS_IS option is missing. Wfuzz might not correctly fuzz URLS with '..'.\n")

except ImportError as e:
    eprint("\nFatal exception: {}. Wfuzz needs pycurl to run. Pycurl could be installed using the following command:\n\npip install pycurl".format(str(e)))
    sys.exit(1)

from .options import FuzzSession
from .api import fuzz, get_payload, get_payloads, encode, decode, payload, get_session
