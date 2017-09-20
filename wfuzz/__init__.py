__title__ = 'wfuzz'
__version__ = "2.2.0"
__build__ = 0x023000
__author__ = 'Xavier Mendez'
__license__ = 'GPL 2.0'
__copyright__ = 'Copyright 2011-2017 Xavier Mendez'

# define a logging Handler
import logging

console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Check for pycurl dependency
import sys

try:
    import pycurl

    if "openssl".lower() not in pycurl.version.lower():
        print "\nWarning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's wiki for more information at https://github.com/xmendez/wfuzz/wiki/PyCurlSSLBug\n"

except ImportError, e:
    print "\nFatal exception: Wfuzz needs pycurl to run. Pycurl could be installed using the following command:\n\npip install pycurl"
    sys.exit(1)

from .options import FuzzSession
from .api import fuzz, get_payload, get_payloads, encode, decode, payload
