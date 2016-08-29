#!/usr/bin/env python

#Covered by GPL V2.0

import sys

# Check for pycurl dependency
try:
    import pycurl

    if "openssl".lower() not in pycurl.version.lower():
        print "\nWarning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's wiki for more information at https://github.com/xmendez/wfuzz/wiki/PyCurlSSLBug\n"

except ImportError, e:
    print "\nFatal exception: Wfuzz needs pycurl to run. Pycurl could be installed using the following command:\n\npip install pycurl"
    sys.exit(1)

import logging
import os

from framework.fuzzer.Fuzzer import Fuzzer
from framework.facade import Facade
from framework.core.options import FuzzSession
from framework.core.myexception import FuzzException

from framework.ui.console.keystroke import KeyPress
from framework.ui.console.controller import Controller
from framework.ui.console.controller import View
from framework.ui.console.clparser import CLParser

kb = None
fz = None
printer = None
session_options = None

# define a logging Handler
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# set current folder in order to load plugins
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

try:
    # parse command line 
    session_options = FuzzSession.from_options(CLParser(sys.argv).parse_cl())

    # Create fuzzer's engine
    fz = Fuzzer(session_options)

    if session_options.get("interactive"):
        # initialise controller
        try:
            kb = KeyPress()
        except ImportError, e:
            raise FuzzException(FuzzException.FATAL, "Error importing necessary modules for interactive mode: %s" % str(e))
        else:
            mc = Controller(fz, kb)
            kb.start()

    printer = View(session_options.get("colour"), session_options.get("verbose"))
    printer.header(fz.genReq.stats)

    for res in fz:
        printer.result(res)

    printer.footer(fz.genReq.stats)
except FuzzException, e:
    print "\nFatal exception: %s" % e.msg
    if fz: fz.cancel_job()
except KeyboardInterrupt:
    print "\nFinishing pending requests..."
    if fz: fz.cancel_job()
except NotImplementedError, e:
    print "\nFatal exception: Error importing wfuzz extensions"
finally:
    if kb: kb.cancel_job()
    Facade().sett.save()
