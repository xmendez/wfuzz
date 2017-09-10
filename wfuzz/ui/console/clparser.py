import sys
import getopt
from collections import defaultdict
import itertools

from wfuzz.filter import PYPARSING
from wfuzz.facade import Facade
from wfuzz.options import FuzzSession
from wfuzz.exception import FuzzException, FuzzExceptBadFile, FuzzExceptBadOptions, FuzzExceptBadInstall
from .common import help_banner
from .common import usage
from .common import brief_usage
from .common import verbose_usage
from wfuzz import __version__ as version
from .output import table_print

class CLParser:
    def __init__(self, argv):
	self.argv = argv

    def show_brief_usage(self):
	print help_banner
	print brief_usage

    def show_verbose_usage(self):
	print help_banner
	print verbose_usage

    def show_usage(self):
	print help_banner
	print usage

    def show_plugins_help(self, registrant, cols=3, category="$all$"):
	print "\nAvailable %s:\n" % registrant
	table_print(map(lambda x: x[cols:], Facade().proxy(registrant).get_plugins_ext(category)))
	sys.exit(0)

    def show_plugin_ext_help(self, registrant, category="$all$"):
        for p in Facade().proxy(registrant).get_plugins(category):
            print "Name: %s %s" % (p.name, p.version)
            print "Categories: %s" % ','.join(p.category)
            print "Summary: %s" % p.summary
            print "Author: %s" % ','.join(p.author)
            print "Description:"
            for l in p.description:
                print "   %s" % l
            print "Parameters:"
            for l in p.parameters:
                print "   %s %s%s: %s" % ("+" if l[2] else "-", l[0], " (= %s)" % str(l[1]) if l[1] else "", l[3])
            print "\n"

	sys.exit(0)

    def parse_cl(self):
	# Usage and command line help
	try:
	    opts, args = getopt.getopt(self.argv[1:], "hLAZX:vcb:e:R:d:z:r:f:t:w:V:H:m:o:s:p:w:u:",['slice=','zP=','oF=','recipe=', 'dump-recipe=', 'req-delay=','conn-delay=','sc=','sh=','sl=','sw=','ss=','hc=','hh=','hl=','hw=','hs=','ntlm=','basic=','digest=','follow','script-help=','script=','script-args=','prefilter=','filter=','interact','help','version','dry-run'])
	    optsd = defaultdict(list)

            payload_cache = {}
	    for i,j in opts:
                if i in ["-z", "--zP", "--slice", "-w"]:
                    if i in ["-z", "-w"]:
                        if payload_cache:
                            optsd["payload"].append(payload_cache)
                            payload_cache = {}

                    payload_cache[i] = j
                optsd[i].append(j)


            if not args and not optsd:
                self.show_brief_usage()
                sys.exit(1)

            if payload_cache:
                optsd["payload"].append(payload_cache)
                payload_cache = {}

	    self._parse_help_opt(optsd)

	    url = None
            if len(args) == 1:
                url = args[0]
            elif len(args) > 1:
                raise FuzzExceptBadOptions("Too many arguments.")

	    options = FuzzSession()

	    if "-u" in optsd:
                if url == "FUZZ":
                    options["seed_payload"] = True
                    url = optsd["-u"][0]
                elif url is None:
                    url = optsd["-u"][0]
                else:
                    raise FuzzExceptBadOptions("Specify the URL either with -u or last argument.")

	    # check command line options correctness
	    self._check_options(optsd)

	    # parse options from recipe first
	    if "--recipe" in optsd:
                options.import_from_file(optsd["--recipe"][0])
		
	    # command line has priority over recipe
	    self._parse_options(optsd, options)
	    self._parse_conn_options(optsd, options)
	    self._parse_filters(optsd, options)
	    self._parse_seed(url, optsd, options)
	    self._parse_payload(optsd, options)
	    self._parse_scripts(optsd, options)

	    if "--dump-recipe" in optsd:
                error = options.validate()
                if error:
                    raise FuzzExceptBadOptions(error)

                options.export_to_file(optsd["--dump-recipe"][0])
                print help_banner
                print "Recipe written to %s." % (optsd["--dump-recipe"][0],)
		sys.exit(0)

	    return options
	except FuzzException, e:
	    self.show_brief_usage()
	    #self.show_usage()
	    raise e
	except ValueError:
	    self.show_brief_usage()
	    raise FuzzExceptBadOptions("Incorrect options, please check help.")
	except getopt.GetoptError, qw:
	    self.show_brief_usage()
	    #self.show_usage()
	    raise FuzzExceptBadOptions("%s." % str(qw))

    def _parse_help_opt(self, optsd):
	if "--version" in optsd:
	    print version
	    sys.exit(0)

	if "-h" in optsd:
	    self.show_usage()
	    sys.exit(0)

	if "--help" in optsd:
	    self.show_verbose_usage()
	    sys.exit(0)

	# Extensions help
	if "--script-help" in optsd:
	    script_string = optsd["--script-help"][0]
	    if script_string == "":
		script_string = "$all$"

            self.show_plugin_ext_help("scripts", category=script_string)

	if "-e" in optsd:
	    if "payloads" in optsd["-e"]:
		self.show_plugins_help("payloads")
	    elif "encoders" in optsd["-e"]:
		self.show_plugins_help("encoders", 2)
	    elif "iterators" in optsd["-e"]:
		self.show_plugins_help("iterators")
	    elif "printers" in optsd["-e"]:
		self.show_plugins_help("printers")
	    elif "scripts" in optsd["-e"]:
		self.show_plugins_help("scripts", 2)
	    else:
		raise FuzzExceptBadOptions("Unknown category. Valid values are: payloads, encoders, iterators, printers or scripts.")

	if "-o" in optsd:
	    if "help" in optsd["-o"]:
		self.show_plugins_help("printers")
	if "-m" in optsd:
	    if "help" in optsd["-m"]:
		self.show_plugins_help("iterators")
	if "-z" in optsd:
	    if "help" in optsd["-z"]:
                filt = optsd["--slice"][0] if "--slice" in optsd else "$all$"
		self.show_plugin_ext_help("payloads", category=filt)


    def _check_options(self, optsd):
	# Check for repeated flags
	l = [i for i in optsd if i not in ["-z", "--zP", "--slice", "payload", "-w", "-b", "-H", "-p"] and len(optsd[i]) > 1]
	if l:
	    raise FuzzExceptBadOptions("Bad usage: Only one %s option could be specified at the same time." % " ".join(l))

	#-A and script not allowed at the same time
	if "--script" in optsd.keys() and "-A" in optsd.keys():
	    raise FuzzExceptBadOptions("Bad usage: --scripts and -A are incompatible options, -A already defines --script=default.")

	if "-s" in optsd.keys() and "-t" in optsd.keys():
	    print "WARNING: When using delayed requests concurrent requests are limited to 1, therefore the -s switch will be ignored."

    def _parse_filters(self, optsd, filter_params):
	'''
	filter_params = dict(
	    hs = None,
	    hc = [],
	    hw = [],
	    hl = [],
	    hh = [],
	    ss = None,
	    sc = [],
	    sw = [],
	    sl = [],
	    sh = [],
	    filter = "",
	    prefilter = "",
	    ),
	'''

	if "--prefilter" in optsd:
	    if not PYPARSING:
		raise FuzzExceptBadInstall("--prefilter switch needs pyparsing module.")
	    filter_params['prefilter'] = optsd["--prefilter"][0]

	if "--filter" in optsd:
	    if not PYPARSING:
		raise FuzzExceptBadInstall("--filter switch needs pyparsing module.")
	    filter_params['filter'] = optsd["--filter"][0]

        if "--hc" in optsd:
            filter_params['hc'] = optsd["--hc"][0].split(",")
        if "--hw" in optsd:
            filter_params['hw'] = optsd["--hw"][0].split(",")
        if "--hl" in optsd:
            filter_params['hl'] = optsd["--hl"][0].split(",")
        if "--hh" in optsd:
            filter_params['hh'] = optsd["--hh"][0].split(",")
        if "--hs" in optsd:
            filter_params['hs'] = optsd["--hs"][0]
 
        if "--sc" in optsd:
            filter_params['sc'] = optsd["--sc"][0].split(",")
        if "--sw" in optsd:
            filter_params['sw'] = optsd["--sw"][0].split(",")
        if "--sl" in optsd:
            filter_params['sl'] = optsd["--sl"][0].split(",")
        if "--sh" in optsd:
            filter_params['sh'] = optsd["--sh"][0].split(",")
        if "--ss" in optsd:
	    filter_params['ss'] = optsd["--ss"][0]

    def _parse_payload(self, optsd, options):
	'''
	options = dict(
	    payloads = [],
	    iterator = None,
	)
	'''

        payloads_list = []

        for payload in optsd["payload"]:
            if "-z" not in payload and "-w" not in payload: 
                raise FuzzExceptBadOptions("--zP and --slice must be preceded by a -z or -w switch.")

            zpayl = payload["-z"] if "-z" in payload else "file,%s" % payload["-w"]
            extraparams = payload["--zP"] if "--zP" in payload else None
            sliceit = payload["--slice"] if "--slice" in payload else None

	    vals = zpayl.split(",")

            default_param = None
            params = {}

            if len(vals) >= 2:
                name, default_param = vals[:2]
            else:
                name = vals[0]

            if extraparams: params = dict(map(lambda x: x.split("=", 1), extraparams.split(",")))
            if default_param: params['default'] = default_param

            encoders = vals[2] if len(vals) == 3 else None

            if encoders:
                params['encoder'] = encoders.split("-")
            elif "encoder" in params:
                params['encoder'] = params['encoder'].split("-")
            else:
                params['encoder'] = None

            payloads_list.append((name, params, sliceit))

	if "-m" in optsd:
	    options["iterator"] = optsd['-m'][0]

        if payloads_list:
            options["payloads"] = payloads_list
            

    def _parse_seed(self, url, optsd, options):
	'''
	options = dict(
	    url = url,
	    method = None,
	    auth = (None, None),
	    follow = False,
	    head = False,
	    postdata = None,
	    headers = [(header, value)],
	    cookie = [],
	    allvars = None,
	)
	'''

	if url:
	    options['url'] = url

	if "-X" in optsd:
	    options['method'] = optsd["-X"][0]

	if "--basic" in optsd:
	    options['auth'] = ("basic", optsd["--basic"][0])

	if "--digest" in optsd:
	    options['auth'] = ("digest", optsd["--digest"][0])

	if "--ntlm" in optsd:
	    options['auth'] = ("ntlm", optsd["--ntlm"][0])

	if "--follow" in optsd or "-L" in optsd:
	    options['follow'] = True

	if "-d" in optsd:
	    options['postdata'] = optsd["-d"][0]

	for bb in optsd["-b"]:
	    options['cookie'].append(bb)

	for x in optsd["-H"]:
	    splitted = x.partition(":")
	    if splitted[1] != ":":
		raise FuzzExceptBadOptions("Wrong header specified, it should be in the format \"name: value\".")
	    options['headers'].append((splitted[0], splitted[2].strip()))

	if "-V" in optsd:
	    options['allvars'] = str(optsd["-V"][0])

    def _parse_conn_options(self, optsd, conn_options):
	'''
	conn_options = dict(
	    proxies = None,
	    conn_delay = 90,
	    req_delay = None,
	    rlevel = 0,
	    scanmode = False,
	    delay = None,
	    concurrent = 10,
	)
	'''

	if "-p" in optsd:
	    proxy = []

            for p in optsd["-p"]:
		vals = p.split(":")

		if len(vals) == 2:
		    proxy.append((vals[0], vals[1], "HTML"))
		elif len(vals) == 3:
		    proxy.append((vals[0], vals[1], vals[2]))
		else:
		    raise FuzzExceptBadOptions("Bad proxy parameter specified.")

	    conn_options['proxies'] = proxy

	if "--conn-delay" in optsd:
	    conn_options['conn_delay'] = int(optsd["--conn-delay"][0])

	if "--req-delay" in optsd:
	    conn_options["req_delay"] = int(optsd["--req-delay"][0])

	if "-R" in optsd:
	    conn_options["rlevel"] = int(optsd["-R"][0])

	if "-Z" in optsd:
	    conn_options["scanmode"] = True

	if "-s" in optsd:
	    conn_options["delay"] = float(optsd["-s"][0])

	if "-t" in optsd:
	    conn_options["concurrent"] = int(optsd["-t"][0])

    def _parse_options(self, optsd, options):
	'''
	options = dict(
	    printer = (None,None),
	    colour = False,
	    interactive = False,
	    dryrun = False,
	    recipe = "",
	)
	'''
	
	if "--oF" in optsd:
	    options["save"] = optsd['--oF'][0]

	if "-v" in optsd:
	    options["verbose"] = True

	if "-c" in optsd:
	    options["colour"] = True

	if "-A" in optsd:
	    options["verbose"] = True
	    options["colour"] = True

	if "-o" in optsd:
	    vals = optsd['-o'][0].split(",", 1)

            if len(vals) == 1:
                options["printer"] = (vals[0], None)
            else:
                options["printer"] = vals
                
	if "--recipe" in optsd:
	    options["recipe"] = optsd['--recipe'][0]

	if "--dry-run" in optsd:
	    options["dryrun"] = True

	if "--interact" in optsd:
	    options["interactive"] = True

    def _parse_scripts(self, optsd, options):
	'''
	options = dict(
	    script = "",
	    script_args = {},
	)
	'''

	if "-A" in optsd:
	    options["script"] = "default"

	if "--script" in optsd:
	    options["script"] = "default" if optsd["--script"][0] == "" else optsd["--script"][0]

	if "--script-args" in optsd:
            try:
                options['script_args'] = dict(map(lambda x: x.split("=", 1), optsd["--script-args"][0].split(",")))
            except ValueError:
                raise FuzzExceptBadOptions("Script arguments: Incorrect arguments format supplied.")
