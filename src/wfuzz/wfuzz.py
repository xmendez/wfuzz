#!/usr/bin/env python
import sys
import warnings

from .core import Fuzzer
from .facade import Facade
from .exception import FuzzException, FuzzExceptBadInstall
from .ui.console.mvc import Controller, KeyPress
from .ui.console.common import (
    help_banner2,
    wfpayload_usage,
)
from .ui.console.clparser import CLParser

from .fuzzobjects import FuzzWordType


def main():
    kb = None
    fz = None
    session_options = None

    try:
        # parse command line
        session_options = CLParser(sys.argv).parse_cl().compile()
        session_options["exec_mode"] = "cli"

        # Create fuzzer's engine
        fz = Fuzzer(session_options)

        if session_options["interactive"]:
            # initialise controller
            try:
                kb = KeyPress()
            except ImportError as e:
                raise FuzzExceptBadInstall(
                    "Error importing necessary modules for interactive mode: %s"
                    % str(e)
                )
            else:
                Controller(fz, kb)
                kb.start()

        for res in fz:
            pass
    except FuzzException as e:
        warnings.warn("Fatal exception: {}".format(str(e)))
    except KeyboardInterrupt:
        warnings.warn("Finishing pending requests...")
        if fz:
            fz.cancel_job()
    except NotImplementedError as e:
        warnings.warn(
            "Fatal exception: Error importing wfuzz extensions: {}".format(str(e))
        )
    except Exception as e:
        warnings.warn("Unhandled exception: {}".format(str(e)))
    finally:
        if session_options:
            session_options.close()
        if kb:
            kb.cancel_job()
        Facade().sett.save()


def main_filter():
    def usage():
        print(help_banner2)
        print(wfpayload_usage)

    from .api import fuzz

    try:
        short_opts = "hvce:z:f:w:o:"
        long_opts = [
            "efield=",
            "ee=",
            "zE=",
            "zD=",
            "field=",
            "slice=",
            "zP=",
            "oF=",
            "recipe=",
            "dump-recipe=",
            "sc=",
            "sh=",
            "sl=",
            "sw=",
            "ss=",
            "hc=",
            "hh=",
            "hl=",
            "hw=",
            "hs=",
            "prefilter=",
            "filter=",
            "help",
            "version",
            "script-help=",
            "script=",
            "script-args=",
        ]
        session_options = CLParser(
            sys.argv,
            short_opts,
            long_opts,
            help_banner2,
            wfpayload_usage,
            wfpayload_usage,
            wfpayload_usage,
        ).parse_cl()
        session_options["transport"] = "payload"
        session_options["url"] = "FUZZ"

        session_options.compile_dictio()
        payload_type = session_options["compiled_dictio"].payloads()[0].get_type()

        if (
            payload_type == FuzzWordType.FUZZRES
            and session_options["show_field"] is not True
        ):
            session_options["exec_mode"] = "cli"

        for res in fuzz(**session_options):
            if payload_type == FuzzWordType.WORD:
                print(res.description)
            elif payload_type == FuzzWordType.FUZZRES and session_options["show_field"]:
                print(res._field())

    except KeyboardInterrupt:
        pass
    except FuzzException as e:
        warnings.warn(("Fatal exception: %s" % str(e)))
    except Exception as e:
        warnings.warn(("Unhandled exception: %s" % str(e)))


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
        warnings.warn(str(err))
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
        warnings.warn(
            "\nFatal exception: Specify a string to encode or decode.{}\n".format(
                str(e)
            )
        )
        sys.exit()
    except AttributeError as e:
        warnings.warn(
            "\nEncoder plugin missing encode or decode functionality. {}".format(str(e))
        )
    except FuzzException as e:
        warnings.warn(("\nFatal exception: %s" % str(e)))


def main_gui():
    import wx
    from .ui.gui.guicontrols import WfuzzFrame
    from .ui.gui.controller import GUIController

    app = wx.App(False)

    frame = WfuzzFrame(None, wx.ID_ANY, "WFuzz wxPython Console", size=(750, 590))
    GUIController(frame)

    frame.Show()
    app.MainLoop()
