#!/usr/bin/env python

#Covered by GPL V2.0

import sys

from .core import Fuzzer
from .facade import Facade
from .exception import FuzzException, FuzzExceptBadInstall

from .ui.console.mvc import Controller, KeyPress, View
from .ui.console.clparser import CLParser

def main():
    kb = None
    fz = None
    printer = None
    session_options = None

    try:
        # parse command line 
        session_options = CLParser(sys.argv).parse_cl().compile()

        # Create fuzzer's engine
        fz = Fuzzer(session_options)

        if session_options["interactive"]:
            # initialise controller
            try:
                kb = KeyPress()
            except ImportError, e:
                raise FuzzExceptBadInstall("Error importing necessary modules for interactive mode: %s" % str(e))
            else:
                mc = Controller(fz, kb)
                kb.start()

        printer = View(session_options["colour"], session_options["verbose"])
        printer.header(fz.genReq.stats)

        for res in fz:
            printer.result(res)

        printer.footer(fz.genReq.stats)
    except FuzzException, e:
        print "\nFatal exception: %s" % str(e)
    except KeyboardInterrupt:
        print "\nFinishing pending requests..."
        if fz: fz.cancel_job()
    except NotImplementedError, e:
        print "\nFatal exception: Error importing wfuzz extensions"
    except Exception, e:
        print "\nUnhandled exception: %s" % str(e)
    finally:
        if kb: kb.cancel_job()
        Facade().sett.save()

def main_filter():
    from .core import dictionary

    session_options = CLParser(sys.argv).parse_cl(check_args=False)

    try:
        for res in dictionary.from_options(session_options):
            r = res[0]
            if "FuzzResult" in str(r.__class__):
                r.description = r.url

            print r

    except KeyboardInterrupt:
        pass
    except FuzzException, e:
        print "\nFatal exception: %s" % str(e)
    except Exception, e:
        print "\nUnhandled exception: %s" % str(e)
