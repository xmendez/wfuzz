#!/usr/bin/env python

#Covered by GPL V2.0

import sys

from .core import Fuzzer
from .facade import Facade
from .options import FuzzSession
from .exception import FuzzException

from .ui.console.mvc import Controller, KeyPress, View
from .ui.console.clparser import CLParser

def main():
    kb = None
    fz = None
    printer = None
    session_options = None

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
    except KeyboardInterrupt:
        print "\nFinishing pending requests..."
        if fz: fz.cancel_job()
    except NotImplementedError, e:
        print "\nFatal exception: Error importing wfuzz extensions"
    finally:
        if kb: kb.cancel_job()
        Facade().sett.save()



