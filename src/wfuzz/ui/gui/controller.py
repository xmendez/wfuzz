import wx
import sys

import cmd

from threading import Thread

if "2.8" in wx.version():
    import wx.lib.pubsub.setupkwargs
    from wx.lib.pubsub import pub
else:
    from wx.lib.pubsub import pub


from wfuzz.ui.console.clparser import CLParser
from wfuzz.ui.gui.model import GUIModel


from wfuzz.facade import Facade

 
class WfuzzInterpreter:
    def __init__(self, model):
        self.model = model

    def onecmd(self, cmd):
        if cmd[0] == "wfuzz":
            self.do_wfuzz(cmd)
        elif cmd[0] == "clear":
            self.model.Clear()
        elif cmd[0] == "wfilter":
            self.do_wfilter(cmd)
        elif cmd[0] == "newtab":
            self.do_tab(cmd)
        elif cmd[0] == "del":
            self.do_delete(cmd)

    def do_wfilter(self, cmd):
        from wfuzz.core import dictionary
        try:
            session_options = CLParser(cmd).parse_cl()
        except SystemExit:
            print "\n"
            pass
        except Exception:
            pass
        else:
            for res in dictionary.from_options(session_options):
                r = res[0]
                if "FuzzResult" in str(r.__class__):
                    r.description = r.url

                self.model.AddRow(r)

    def do_wfuzz(self, cmd):
        try:
            session_options = CLParser(cmd).parse_cl().compile()
        except SystemExit:
            print "\n"
            pass
        except Exception:
            pass
        else:
            for res in session_options.fuzz():
                self.model.AddRow(res)

    def do_delete(self, cmd):
        self.model.DeleteRows_by_filter(cmd[1])

    def do_tab(self, cmd):
        data = Facade().data[cmd[1]] = []
        model=GUIModel(data)
        pub.sendMessage("create_tab", name=cmd[1], model=model, interp=WfuzzInterpreter(model))


from wx.py.interpreter import Interpreter


class WfuzzInterpreter2(Interpreter):
    def __init__(self, locals, rawin, stdin, stdout, stderr):

        Interpreter.__init__(self, locals, rawin, stdin, stdout, stderr, True)

        self.introText = "Welcome to wfuzz GUI console"

    def do_wfuzz(self, cmd):
        try:
            session_options = CLParser(cmd).parse_cl().compile()
        except SystemExit:
            print "\n"
            pass
        except Exception:
            pass
        else:
            for res in session_options.fuzz():
                self.model.AddRow(res)

    def runsource(self, source):
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        sys.stdin, sys.stdout, sys.stderr = \
                   self.stdin, self.stdout, self.stderr
        more = False

        import shlex
        cmd = shlex.split(source)
        do_wfuzz(cmd)
        # this was a cute idea, but didn't work...
        #more = self.runcode(compile(source,'',
        #               ('exec' if self.useExecMode else 'single')))
        
        
        # If sys.std* is still what we set it to, then restore it.
        # But, if the executed source changed sys.std*, assume it was
        # meant to be changed and leave it. Power to the people.
        if sys.stdin == self.stdin:
            sys.stdin = stdin
        else:
            self.stdin = sys.stdin
        if sys.stdout == self.stdout:
            sys.stdout = stdout
        else:
            self.stdout = sys.stdout
        if sys.stderr == self.stderr:
            sys.stderr = stderr
        else:
            self.stderr = sys.stderr
        return more



class GUIController:
    def __init__(self, view):
        Facade().mode = "gui"
        self.data = Facade().data = {"main": []}
        self._model = GUIModel(self.data["main"])

        self._view = view
        self._interp = WfuzzInterpreter2
        self._interp = WfuzzInterpreter(self._model)

        # init gui
        self.start_gui()

        pub.subscribe(self.on_exit, "exit")

    def start_gui(self):
        self._view.start_gui(self)

    def on_exit(self, msg):
        print "oooo"
