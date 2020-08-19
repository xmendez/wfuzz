import wx
import wx.py
import wx.grid
import wx.aui
import wx.html

import wx.lib.agw.aui as aui
import wx.dataview as dv
import wx.html2 as webview

if "2.8" in wx.version():
    import wx.lib.pubsub.setupkwargs
    from wx.lib.pubsub import pub
else:
    from wx.lib.pubsub import pub

try:
    from agw import pycollapsiblepane as PCP
except ImportError:  # if it's not there locally, try the wxPython lib.
    import wx.lib.agw.pycollapsiblepane as PCP

# puedo no hacer paneles y devolverlos directamente como hace el treectrl, no se cual es la ventaja really

# ----------------------------------------------------------------------
# http://stackoverflow.com/questions/22265868/how-to-create-a-cmd-with-wxpython
# esto puede hacer q meta cmd.cmd directamente https://www.blog.pythonlibrary.org/2009/01/01/wxpython-redirecting-stdout-stderr/


class RedirectText(object):
    def __init__(self, aWxTextCtrl):
        self.out = aWxTextCtrl

    def write(self, string):
        self.out.WriteText(string)


class ConsolePanel(wx.Panel):
    def __init__(self, parent, interpreter):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent, -1)

        self.history = []
        self.index = 0

        self.prompt = ">>"
        self.textctrl = wx.TextCtrl(
            self,
            -1,
            "",
            style=wx.TE_PROCESS_ENTER | wx.TE_MULTILINE | wx.TE_RICH,
            size=(-1, 250),
        )
        self.textctrl.SetForegroundColour(wx.WHITE)
        self.textctrl.SetBackgroundColour(wx.BLACK)

        self.textctrl.AppendText(self.prompt)

        self.textctrl.Bind(wx.EVT_CHAR, self.__bind_events)

        sizer = wx.BoxSizer()
        sizer.Add(self.textctrl, 1, wx.EXPAND)
        self.SetSizer(sizer)

        self._interp = interpreter
        redir = RedirectText(self.textctrl)

        import sys

        # Create a replacement for stdin.
        # self.reader = PseudoFileIn(self.readline, self.readlines)
        # self.reader.input = ''
        # self.reader.isreading = False

        # sys.stdin=self.reader
        sys.stdout = redir
        sys.stderr = redir

    def __bind_events(self, e):
        if e.GetKeyCode() == 13:
            self.index = len(self.history) - 1

            self.value = self.textctrl.GetValue()
            ln = self.get_last_line()

            ln = ln.strip()
            if ln not in self.history:
                self.history.append(ln)
            self.index += 1
            if ln:
                import shlex

                cmd = shlex.split(ln)
                # out en retvalue
                retvalue = self._interp.onecmd(cmd)
                if retvalue:
                    self.textctrl.WriteText("\n")
                    self.textctrl.AppendText(retvalue)

            self.textctrl.WriteText("\n")
            self.textctrl.WriteText(self.prompt)
        # down
        elif e.GetKeyCode() == 317:
            self.index += 1

            if self.index >= len(self.history):
                self.index = len(self.history) - 1

            self.textctrl.WriteText("\n")
            self.textctrl.WriteText(self.prompt)
            self.textctrl.WriteText(self.history[self.index])

        # up
        elif e.GetKeyCode() == 315:
            self.index -= 1

            if self.index < 0:
                self.index = 0

            self.textctrl.WriteText("\n")
            self.textctrl.WriteText(self.prompt)
            self.textctrl.WriteText(self.history[self.index])
        else:
            e.Skip()

    def get_last_line(self):
        nl = self.textctrl.GetNumberOfLines()
        ln = self.textctrl.GetLineText(nl - 1)
        ln = ln[len(self.prompt) :]

        return ln


# ----------------------------------------------------------------------


class ListPanel(wx.Panel):
    def __init__(self, parent, log, model, interpreter):
        self.log = log
        self._interp = interpreter
        wx.Panel.__init__(self, parent, -1)

        self.dvc = dv.DataViewCtrl(
            self, style=wx.BORDER_THEME | dv.DV_ROW_LINES | dv.DV_VERT_RULES
        )

        self.model = model
        self.dvc.AssociateModel(self.model)

        for row in list(self.model.row_mapper.values()):
            self.dvc.AppendTextColumn(row.title, row.colid, width=row.width)

        for c in self.dvc.Columns:
            c.Sortable = True
            c.Reorderable = True

        self.cp = cp = PCP.PyCollapsiblePane(
            self, label="Show console", agwStyle=wx.CP_GTK_EXPANDER
        )
        self.MakePaneContent(cp.GetPane())

        self.Sizer = wx.BoxSizer(wx.VERTICAL)
        self.Sizer.Add(self.dvc, 1, wx.EXPAND)
        self.Sizer.Add(cp, 0, wx.RIGHT | wx.LEFT | wx.EXPAND)
        self.SetSizer(self.Sizer)
        self.SetAutoLayout(True)

        self.dvc.Bind(dv.EVT_DATAVIEW_SELECTION_CHANGED, self.OnItemSelected)

    def OnItemSelected(self, event):
        try:
            items = self.dvc.GetSelections()
            item = self.model.GetRow(items[0])
        except IndexError:
            pass
        else:
            pub.sendMessage("selected_row", row=self.model.data[item])

        event.Skip()

    def MakePaneContent(self, pane):
        border = wx.BoxSizer()
        border.Add(ConsolePanel(pane, self._interp), wx.RIGHT | wx.LEFT | wx.EXPAND)
        # border.Add(py.shell.Shell(pane, InterpClass=self._interp, size=(-1,250)),  wx.RIGHT|wx.LEFT|wx.EXPAND)

        pane.SetSizer(border)


class HttpRawPanel(wx.Panel):
    def __init__(self, parent, frame):
        self._frame = frame
        wx.Panel.__init__(self, parent, -1)

        # self.req_txt = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE|wx.TE_READONLY)
        self.req_txt = webview.WebView.New(self)
        # self.resp_txt = webview.WebView.New(self)
        self.resp_txt = wx.TextCtrl(
            self, -1, "", style=wx.TE_MULTILINE | wx.TE_READONLY
        )

        sizer = wx.BoxSizer(wx.HORIZONTAL)

        sizer.Add(self.req_txt, 1, wx.EXPAND)
        sizer.Add(self.resp_txt, 1, wx.EXPAND)

        self.SetSizer(sizer)
        self.SetAutoLayout(True)

    def CreateHTMLCtrl(self):
        ctrl = wx.html.HtmlWindow(self, -1, wx.DefaultPosition, wx.Size(400, 300))
        if "gtk2" in wx.PlatformInfo or "gtk3" in wx.PlatformInfo:
            ctrl.SetStandardFonts()

        ctrl.SetPage("")

        return ctrl


class MainNotebookPanel(wx.Panel):
    def __init__(self, parent, frame, interpreter):
        self._frame = frame
        wx.Panel.__init__(self, parent, -1)

        bookStyle = aui.AUI_NB_DEFAULT_STYLE
        bookStyle &= ~(aui.AUI_NB_CLOSE_ON_ACTIVE_TAB)

        self.rawpanel = HttpRawPanel(self, self)
        self.renderpanel = self.create_web_view()

        self.nb = aui.AuiNotebook(self, style=bookStyle)
        self.nb.AddPage(self.rawpanel, "HTML Raw")
        self.nb.AddPage(self.renderpanel, "HTML Render")

        sizer = wx.BoxSizer()
        sizer.Add(self.nb, 1, wx.EXPAND)
        self.SetSizer(sizer)
        wx.CallAfter(self.nb.SendSizeEvent)

        pub.subscribe(self.on_selected_row, "selected_row")

    def create_web_view(self):
        return webview.WebView.New(self)

    def on_selected_row(self, row):
        from pygments import highlight
        from pygments.lexers import get_lexer_by_name
        from pygments.formatters import HtmlFormatter

        result = highlight(
            str(row.history), get_lexer_by_name("http"), HtmlFormatter(full=True)
        )
        # result2 = highlight(str(row.history.raw_content), get_lexer_by_name("http"), HtmlFormatter(full=True))

        self.renderpanel.SetPage(row.history.content, row.url)
        # self.rawpanel.req_txt.SetValue(str(row.history))
        self.rawpanel.req_txt.SetPage(result, "")
        # self.rawpanel.resp_txt.SetPage(result2, "")
        self.rawpanel.resp_txt.SetValue(str(row.history.raw_content))


# ----------------------------------------------------------------------


ID_About = wx.NewId()


class WfuzzFrame(wx.Frame):
    def __init__(
        self,
        parent,
        id=-1,
        title="Wfuzz",
        pos=wx.DefaultPosition,
        size=wx.DefaultSize,
        style=wx.DEFAULT_FRAME_STYLE | wx.SUNKEN_BORDER | wx.CLIP_CHILDREN,
    ):
        wx.Frame.__init__(self, parent, id, title, pos, size, style)

    def start_gui(self, controller):
        self.controller = controller
        # tell FrameManager to manage this frame
        self._mgr = wx.aui.AuiManager()
        self._mgr.SetManagedWindow(self)

        # create menu
        mb = wx.MenuBar()

        file_menu = wx.Menu()
        file_menu.Append(wx.ID_EXIT, "Exit")

        help_menu = wx.Menu()
        help_menu.Append(ID_About, "About...")

        mb.Append(file_menu, "File")
        mb.Append(help_menu, "Help")

        self.SetMenuBar(mb)

        self.SetMinSize(wx.Size(400, 300))

        # create some center panes
        self._mgr.AddPane(
            MainNotebookPanel(self, self, controller._interp),
            wx.aui.AuiPaneInfo()
            .Caption("Raw HTTP Content")
            .Name("analysis_notebook")
            .CenterPane(),
        )
        self._mgr.AddPane(
            self.CreateNotebook(),
            wx.aui.AuiPaneInfo().Name("main_notebook").CenterPane(),
        )
        self._mgr.Update()

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.Bind(wx.EVT_MENU, self.OnExit, id=wx.ID_EXIT)
        self.Bind(wx.EVT_MENU, self.OnAbout, id=ID_About)

        pub.subscribe(self.OnAddTab, "create_tab")

    def OnClose(self, event):
        pub.sendMessage("exit", msg="exiting...")
        self._mgr.UnInit()
        del self._mgr
        self.Destroy()

    def OnExit(self, event):
        pub.sendMessage("exit", msg="exiting...")
        self.Close()

    def OnAbout(self, event):
        msg = "WFuzz GUI\n(c) Copyright 2017, Xavi Mendez"
        dlg = wx.MessageDialog(self, msg, "About", wx.OK | wx.ICON_INFORMATION)
        dlg.ShowModal()
        dlg.Destroy()

    def CreateNotebook(self):
        bookStyle = aui.AUI_NB_DEFAULT_STYLE
        # bookStyle &= ~(aui.AUI_NB_CLOSE_ON_ACTIVE_TAB)

        bookStyle = (
            aui.AUI_NB_DEFAULT_STYLE | aui.AUI_NB_TAB_EXTERNAL_MOVE | wx.NO_BORDER
        )

        client_size = self.GetClientSize()
        nb = aui.AuiNotebook(
            self,
            -1,
            wx.Point(client_size.x, client_size.y),
            wx.Size(430, 200),
            agwStyle=bookStyle,
        )

        nb.AddPage(
            ListPanel(self, self, self.controller._model, self.controller._interp),
            "Main",
        )

        return nb

    def OnAddTab(self, name, model, interp):
        auibook = self._mgr.GetPane("main_notebook").window

        auibook.AddPage(ListPanel(self, self, model, interp), name, True)

        self._mgr.Update()
