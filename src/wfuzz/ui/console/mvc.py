import sys
from collections import defaultdict
import threading

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from wfuzz.fuzzobjects import FuzzWordType, FuzzType

from .common import exec_banner, Term
from .getch import _Getch
from .output import getTerminalSize, wrap_always_list

usage = """\r\n
Interactive keyboard commands:\r\n
?: Show this help

p: Pause
s: Show stats
q: Cancel
"""


class SimpleEventDispatcher:
    def __init__(self):
        self.publisher = defaultdict(list)

    def create_event(self, msg):
        self.publisher[msg] = []

    def subscribe(self, func, msg, dynamic=False):
        if msg not in self.publisher and not dynamic:
            raise KeyError("subscribe. No such event: %s" % (msg))
        else:
            self.publisher[msg].append(func)

    def notify(self, msg, **event):
        if msg not in self.publisher:
            raise KeyError("notify. Event not subscribed: %s" % (msg,))
        else:
            for functor in self.publisher[msg]:
                functor(**event)


class KeyPress(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.inkey = _Getch()
        self.setName("KeyPress")

        self.dispatcher = SimpleEventDispatcher()
        self.dispatcher.create_event("?")
        self.dispatcher.create_event("p")
        self.dispatcher.create_event("s")
        self.dispatcher.create_event("q")

        self.do_job = True

    def cancel_job(self):
        self.do_job = False

    def run(self):
        while self.do_job:
            k = self.inkey()
            if k and ord(k) == 3:
                self.dispatcher.notify("q", key="q")
            elif k == "p":
                self.dispatcher.notify("p", key="p")
            elif k == "s":
                self.dispatcher.notify("s", key="s")
            elif k == "?":
                self.dispatcher.notify("?", key="?")
            elif k == "q":
                self.dispatcher.notify("q", key="q")


class Controller:
    def __init__(self, fuzzer, view):
        self._debug = False
        self.fuzzer = fuzzer
        self.view = view
        self.__paused = False

        self.view.dispatcher.subscribe(self.on_help, "?")
        self.view.dispatcher.subscribe(self.on_pause, "p")
        self.view.dispatcher.subscribe(self.on_stats, "s")
        self.view.dispatcher.subscribe(self.on_exit, "q")

    # dynamic keyboard bindings
    def on_exit(self, **event):
        self.fuzzer.cancel_job()
        self.fuzzer.genReq.stats.mark_end()
        self.view.cancel_job()

    def on_help(self, **event):
        print(usage)

    def on_pause(self, **event):
        self.__paused = not self.__paused
        if self.__paused:
            self.fuzzer.pause_job()

            if self._debug:
                print("\n=============== Paused ==================")
                stats = self.fuzzer.stats()
                for k, v in list(stats.items()):
                    print("%s: %s" % (k, v))
                print("\n=========================================")
        else:
            self.fuzzer.resume_job()

    def on_stats(self, **event):
        if self._debug:
            print("\n=============== Paused ==================")
            stats = self.fuzzer.stats()
            for k, v in list(stats.items()):
                print("%s: %s" % (k, v))
            print("\n=========================================")
        else:
            pending = (
                self.fuzzer.genReq.stats.total_req
                - self.fuzzer.genReq.stats.processed()
            )
            summary = self.fuzzer.genReq.stats
            summary.mark_end()
            print("\nTotal requests: %s\r" % str(summary.total_req))
            print("Pending requests: %s\r" % str(pending))

            if summary.backfeed() > 0:
                print(
                    "Processed Requests: %s (%d + %d)\r"
                    % (
                        str(summary.processed())[:8],
                        (summary.processed() - summary.backfeed()),
                        summary.backfeed(),
                    )
                )
            else:
                print("Processed Requests: %s\r" % (str(summary.processed())[:8]))
            print("Filtered Requests: %s\r" % (str(summary.filtered())[:8]))
            req_sec = (
                summary.processed() / summary.totaltime if summary.totaltime > 0 else 0
            )
            print("Total time: %s\r" % str(summary.totaltime)[:8])
            if req_sec > 0:
                print("Requests/sec.: %s\r" % str(req_sec)[:8])
                eta = pending / req_sec
                if eta > 60:
                    print("ET left min.: %s\r\n" % str(eta / 60)[:8])
                else:
                    print("ET left sec.: %s\r\n" % str(eta)[:8])


class View:
    widths = [10, 8, 6, 6, 9, getTerminalSize()[0] - 65]
    verbose_widths = [10, 10, 8, 6, 6, 9, 30, 30, getTerminalSize()[0] - 145]

    def __init__(self, session_options):
        self.colour = session_options["colour"]
        self.verbose = session_options["verbose"]
        self.previous = session_options["previous"]
        self.term = Term()
        self.printed_lines = 0

    def _print_verbose(self, res, print_nres=True):
        txt_colour = (
            Term.noColour if not res.is_baseline or not self.colour else Term.fgCyan
        )
        if self.previous and self.colour and not print_nres:
            txt_colour = Term.fgCyan

        location = ""
        if "Location" in res.history.headers.response:
            location = res.history.headers.response["Location"]
        elif res.history.url != res.history.redirect_url:
            location = "(*) %s" % res.history.url

        server = ""
        if "Server" in res.history.headers.response:
            server = res.history.headers.response["Server"]

        rows = [
            ("%09d:" % res.nres if print_nres else " |_", txt_colour),
            ("%.3fs" % res.timer, txt_colour),
            (
                "%s" % "XXX" if res.exception else str(res.code),
                self.term.get_colour(res.code) if self.colour else txt_colour,
            ),
            ("%d L" % res.lines, txt_colour),
            ("%d W" % res.words, txt_colour),
            ("%d Ch" % res.chars, txt_colour),
            (server, txt_colour),
            (location, txt_colour),
            ('"%s"' % res.description, txt_colour),
        ]

        self.term.set_colour(txt_colour)
        self.printed_lines = self._print_line(rows, self.verbose_widths)

    def _print_header(self, rows, maxWidths):
        print("=" * (3 * len(maxWidths) + sum(maxWidths[:-1]) + 10))
        self._print_line(rows, maxWidths)
        print("=" * (3 * len(maxWidths) + sum(maxWidths[:-1]) + 10))
        print("")

    def _print_line(self, rows, maxWidths):
        def wrap_row(rows, maxWidths):
            newRows = [
                wrap_always_list(item[0], width) for item, width in zip(rows, maxWidths)
            ]
            return [[substr or "" for substr in item] for item in zip_longest(*newRows)]

        def print_row(row, rows):
            sys.stdout.write(
                "   ".join(
                    [
                        colour + str.ljust(str(item), width) + Term.reset
                        for (item, width, colour) in zip(
                            row, maxWidths, [colour[1] for colour in rows]
                        )
                    ]
                )
            )

        new_rows = wrap_row(rows, maxWidths)

        for row in new_rows:
            print_row(row, rows)
            sys.stdout.write("\n\r")

        sys.stdout.flush()
        return len(new_rows)

    def _print(self, res, print_nres=True):
        txt_colour = (
            Term.noColour if not res.is_baseline or not self.colour else Term.fgCyan
        )
        if self.previous and self.colour and not print_nres:
            txt_colour = Term.fgCyan

        rows = [
            ("%09d:" % res.nres if print_nres else " |_", txt_colour),
            (
                "%s" % "XXX" if res.exception else str(res.code),
                self.term.get_colour(res.code) if self.colour else txt_colour,
            ),
            ("%d L" % res.lines, txt_colour),
            ("%d W" % res.words, txt_colour),
            ("%d Ch" % res.chars, txt_colour),
            ('"%s"' % res.description, txt_colour),
        ]

        self.term.set_colour(txt_colour)
        self.printed_lines = self._print_line(rows, self.widths)

    def header(self, summary):
        print(exec_banner)
        if summary:
            print("Target: %s\r" % summary.url)
            if summary.total_req > 0:
                print("Total requests: %d\r\n" % summary.total_req)
            else:
                print("Total requests: <<unknown>>\r\n")

        if self.verbose:
            rows = [
                ("ID", Term.noColour),
                ("C.Time", Term.noColour),
                ("Response", Term.noColour),
                ("Lines", Term.noColour),
                ("Word", Term.noColour),
                ("Chars", Term.noColour),
                ("Server", Term.noColour),
                ("Redirect", Term.noColour),
                ("Payload", Term.noColour),
            ]

            widths = self.verbose_widths
        else:
            rows = [
                ("ID", Term.noColour),
                ("Response", Term.noColour),
                ("Lines", Term.noColour),
                ("Word", Term.noColour),
                ("Chars", Term.noColour),
                ("Payload", Term.noColour),
            ]

            widths = self.widths

        self._print_header(rows, widths)

    def result(self, res):
        if self.verbose:
            self._print_verbose(res)
        else:
            self._print(res)

        if res.item_type == FuzzType.RESULT:
            if (
                self.previous
                and res.payload_man
                and res.payload_man.get_payload_type(1) == FuzzWordType.FUZZRES
            ):
                prev_res = res.payload_man.get_payload_content(1)
                if self.verbose:
                    self._print_verbose(prev_res, print_nres=False)
                else:
                    self._print(prev_res, print_nres=False)

            if res.plugins_res:
                for i in res.plugins_res:
                    sys.stdout.write(" |_  %s\r" % i.issue)
                    sys.stdout.write("\n\r")

            self.printed_lines = 0

        if self.printed_lines > 0:
            self.term.erase_lines(self.printed_lines + 1)

    def footer(self, summary):
        sys.stdout.write("\n\r")

        print(summary)
