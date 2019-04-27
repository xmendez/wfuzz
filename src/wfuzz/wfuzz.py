#!/usr/bin/env python
import sys

from .core import Fuzzer
from .facade import Facade
from .exception import FuzzException, FuzzExceptBadInstall

from .ui.console.mvc import Controller, KeyPress, View
from .ui.console.common import help_banner2
from .ui.console.clparser import CLParser

from .fuzzobjects import FuzzResult


def main():
    kb = None
    fz = None
    printer = None
    session_options = None

    try:
        # parse command line
        session_options = CLParser(sys.argv).parse_cl().compile()
        session_options["send_discarded"] = True

        # Create fuzzer's engine
        fz = Fuzzer(session_options)

        if session_options["interactive"]:
            # initialise controller
            try:
                kb = KeyPress()
            except ImportError as e:
                raise FuzzExceptBadInstall("Error importing necessary modules for interactive mode: %s" % str(e))
            else:
                Controller(fz, kb)
                kb.start()

        printer = View(session_options)
        if session_options["console_printer"]:
            printer = Facade().printers.get_plugin(session_options["console_printer"])(None)
        printer.header(fz.genReq.stats)

        for res in fz:
            printer.result(res)

        printer.footer(fz.genReq.stats)
    except FuzzException as e:
        print("\nFatal exception: {}".format(str(e)))
    except KeyboardInterrupt:
        print("\nFinishing pending requests...")
        if fz:
            fz.cancel_job()
    except NotImplementedError as e:
        print("\nFatal exception: Error importing wfuzz extensions: {}".format(str(e)))
    except Exception as e:
        print("\nUnhandled exception: {}".format(str(e)))
    finally:
        if session_options:
            session_options.close()
        if kb:
            kb.cancel_job()
        Facade().sett.save()


def main_filter():
    def usage():
        print(help_banner2)
        print("""Usage:
\n\twfpayload [Options]\n\n
\nOptions:\n
\t--help              : This help
\t-v                  : Verbose output
\t-z payload          : Specify a payload for each FUZZ keyword used in the form of type,parameters,encoder.
\t		      A list of encoders can be used, ie. md5-sha1. Encoders can be chained, ie. md5@sha1.
\t		      Encoders category can be used. ie. url
\t--zD default	    : Default argument for the specified payload (it must be preceded by -z or -w).
\t--zP <params>	    : Arguments for the specified payload (it must be preceded by -z or -w).
\t--slice <filter>    : Filter payload\'s elements using the specified expression.
\t-w wordlist         : Specify a wordlist file (alias for -z file,wordlist).
\t-m iterator         : Specify an iterator for combining payloads (product by default)
\t--field <expr>      : Do not show the payload but the specified language expression
\t--efield <expr>     : Show the specified language expression together with the current payload
""")

    from .api import payload
    from .exception import FuzzExceptBadOptions
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "vhz:m:w:", ["field=", "help", "slice=", "zD=", "zP=", "efield="])
    except getopt.GetoptError as err:
        print((str(err)))
        usage()
        sys.exit(2)

    if len(opts) == 0 or len(args) > 0:
        usage()
        sys.exit()

    field = None
    raw_output = False

    for o, value in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        if o in ("--efield"):
            field = value
        if o in ("--field"):
            field = value
            raw_output = True

    try:
        session_options = CLParser(sys.argv).parse_cl()
        printer = None

        for res in payload(**session_options):
            if len(res) > 1:
                raise FuzzExceptBadOptions("wfpayload can only be used to generate one word dictionaries")
            else:
                r = res[0]

            # TODO: all should be same object type and no need for isinstance
            if isinstance(r, FuzzResult):
                if raw_output:
                    print(r.eval(field if field is not None else "url"))
                else:
                    if printer is None:
                        printer = View(session_options)
                        printer.header(None)

                    if field:
                        r._description = field
                        r._show_field = False
                    printer.result(r)
            else:
                print(r)

    except KeyboardInterrupt:
        pass
    except FuzzException as e:
        print(("\nFatal exception: %s" % str(e)))
    except Exception as e:
        print(("\nUnhandled exception: %s" % str(e)))


def main_encoder():
    def usage():
        print(help_banner2)
        print("Usage:")
        print("\n\twfencode --help This help")
        print("\twfencode -d decoder_name string_to_decode")
        print("\twfencode -e encoder_name string_to_encode")
        print()

    from .api import encode, decode
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "he:d:", ["help"])
    except getopt.GetoptError as err:
        print((str(err)))
        usage()
        sys.exit(2)

    if len(args) == 0:
        usage()
        sys.exit()

    try:
        for o, value in opts:
            if o == "-e":
                print((encode(value, args[0])))
            elif o == "-d":
                print((decode(value, args[0])))
            elif o in ("-h", "--help"):
                usage()
                sys.exit()
    except IndexError as e:
        usage()
        print("\nFatal exception: Specify a string to encode or decode.{}\n".format(str(e)))
        sys.exit()
    except AttributeError as e:
        print("\nEncoder plugin missing encode or decode functionality. {}".format(str(e)))
    except FuzzException as e:
        print(("\nFatal exception: %s" % str(e)))


def main_gui():
    import wx
    from .ui.gui.guicontrols import WfuzzFrame
    from .ui.gui.controller import GUIController

    app = wx.App(False)

    frame = WfuzzFrame(None, wx.ID_ANY, "WFuzz wxPython Console", size=(750, 590))
    GUIController(frame)

    frame.Show()
    app.MainLoop()
