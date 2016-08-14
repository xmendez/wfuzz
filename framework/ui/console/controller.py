import sys

from framework.ui.console.common import exec_banner, Term
from framework.core.facade import Facade

usage='''\r\n
Interactive keyboard commands:\r\n
?: Show this help

p: Pause
s: Show stats
q: Cancel
'''

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
	self.fuzzer.genReq.stats.mark_end()
	self.fuzzer.cancel_job()
	#self.view.cancel_job()
	#self.view.cancel_job()

    def on_help(self, **event):
	print usage

    def on_pause(self, **event):
	self.__paused = not self.__paused
	if self.__paused:
	    self.fuzzer.pause_job()

	    if self._debug:
		print "\n=============== Paused =================="
		stats = self.fuzzer.stats()
		for k,v in stats.items():
		    print "%s: %s" % (k, v)
		print "\n========================================="
	else:
	    self.fuzzer.resume_job()

    def on_stats(self, **event):
	if self._debug:
	    fzstats = self.fuzzer.stats()

	    print "\nTotal items %d, Backfed items %d, HTTP reqs: %d, Fuzzed items: %d, Pending: %d (Wait HTTP: %d, Wait pre HTTP: %d, Wait Workers: %d, Wait processed: %d). (MEM: %d)" % \
		(fzstats['total'], \
		fzstats['backfed'], \
		fzstats['http_Processed'], \
		fzstats['Processed'], \
		fzstats['Pending'], \
		fzstats['http_Pending'], \
		fzstats['http_queue'], \
		fzstats['plugins_queue'], \
		fzstats['results_queue'],
		)
	else:
	    pending = self.fuzzer.genReq.stats.total_req - self.fuzzer.genReq.stats.processed
	    summary = self.fuzzer.genReq.stats
	    summary.mark_end()
	    print "\nTotal requests: %s\r" % str(summary.total_req)
	    print "Pending requests: %s\r" % str(pending)

	    if summary.backfeed > 0:
		print "Processed Requests: %s (%d + %d)\r" % (str(summary.processed)[:8], (summary.processed - summary.backfeed), summary.backfeed)
	    else:
		print "Processed Requests: %s\r" % (str(summary.processed)[:8])
	    print "Filtered Requests: %s\r" % (str(summary.filtered)[:8])
	    req_sec = summary.processed/summary.totaltime if summary.totaltime > 0 else 0
	    print "Total time: %s\r" % str(summary.totaltime)[:8]
	    if req_sec > 0:
		print "Requests/sec.: %s\r" % str(req_sec)[:8]
		eta = pending/req_sec
		if eta > 60:
		    print "ET left min.: %s\r\n" % str(eta/60)[:8]
		else:
		    print "ET left sec.: %s\r\n" % str(eta)[:8]

class View:
    def __init__(self, colour, verbose):
        self.colour = colour
        self.verbose = verbose
        self.term = Term()

    def _print_verbose(self, res):
	txt_colour = ("", 8) if not res.is_baseline or not self.colour else (Term.fgCyan, 8)

        self.term.set_colour(txt_colour)

	self.term.write("%05d:  " % (res.nres), txt_colour)
	self.term.write("%.3fs   C=" % (res.timer), txt_colour)

	location = ""
	if 'Location' in res.history.headers.response:
	    location = res.history.headers.response['Location']
	elif res.history.url != res.history.redirect_url:
	    location = "(*) %s" % res.history.url

	server = ""
	if 'Server' in res.history.headers.response:
	    server = res.history.headers.response['Server']

	if res.exception:
	    self.term.write("XXX", self.term.get_colour(res.code) if self.colour else ("",8))
	else:
	    self.term.write("%03d" % (res.code), self.term.get_colour(res.code) if self.colour else ("",8))

	self.term.write("   %4d L\t   %5d W\t  %5d Ch  %20.20s  %51.51s   \"%s\"" % (res.lines, res.words, res.chars, server[:17], location[:48], res.description), txt_colour)

	sys.stdout.flush()


    def _print(self, res):
	txt_colour = ("", 8) if not res.is_baseline or not self.colour else (Term.fgCyan, 8)

        self.term.set_colour(txt_colour)

        self.term.write("%05d:  C=" % (res.nres), txt_colour)
	if res.exception:
	    self.term.write("XXX", self.term.get_colour(res.code) if self.colour else ("",8))
	else:
	    self.term.write("%03d" % (res.code), self.term.get_colour(res.code) if self.colour else ("",8))
	self.term.write("   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"" % (res.lines, res.words, res.chars, res.description), txt_colour)

	sys.stdout.flush()

    def header(self, summary):
	print exec_banner
	print "Target: %s\r" % summary.url
	#print "Payload type: " + payloadtype + "\n"
	#print "Total requests:aaaaaaa %d\r\n" % summary.total_req
	if summary.total_req > 0:
	    print "Total requests: %d\r\n" % summary.total_req
	else:
		print "Total requests: <<unknown>>\r\n"

        if self.verbose:
            print "==============================================================================================================================================\r"
            print "ID	C.Time   Response   Lines      Word         Chars                  Server                                             Redirect   Payload    \r"
            print "==============================================================================================================================================\r\n"
        else:
            print "==================================================================\r"
            print "ID	Response   Lines      Word         Chars          Request    \r"
            print "==================================================================\r\n"

    def result(self, res):
        self.term.delete_line()

        if self.verbose:
            self._print_verbose(res)
        else:
            self._print(res)

        if res.is_visible: 
            sys.stdout.write("\n\r")

            for i in res.plugins_res:
                print "  |_ %s\r" % i.issue

    def footer(self, summary):
        self.term.delete_line()
	sys.stdout.write("\r\n")

	print "Total time: %s\r" % str(summary.totaltime)[:8]

	if summary.backfeed > 0:
	    print "Processed Requests: %s (%d + %d)\r" % (str(summary.processed)[:8], (summary.processed - summary.backfeed), summary.backfeed)
	else:
	    print "Processed Requests: %s\r" % (str(summary.processed)[:8])
	print "Filtered Requests: %s\r" % (str(summary.filtered)[:8])
	print "Requests/sec.: %s\r\n" % str(summary.processed/summary.totaltime if summary.totaltime > 0 else 0)[:8]

