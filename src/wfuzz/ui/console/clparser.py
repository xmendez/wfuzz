import re
import sys
import getopt
import warnings
from collections import defaultdict

from wfuzz.helpers.file_func import get_filter_help_file
from wfuzz.helpers.obj_dyn import allowed_fields
from wfuzz.filters.ppfilter import PYPARSING
from wfuzz.facade import Facade
from wfuzz.options import FuzzSession
from wfuzz.exception import FuzzException, FuzzExceptBadOptions, FuzzExceptBadInstall
from .common import help_banner, exec_banner
from .common import usage
from .common import brief_usage
from .common import verbose_usage
from wfuzz import __version__ as version
from .output import table_print

short_opts = "hLAZX:vcb:e:R:D:d:z:r:f:t:w:V:H:m:f:o:s:p:w:u:"
long_opts = [
    "efield=",
    "no-cache",
    "ee=",
    "zE=",
    "zD=",
    "field=",
    "ip=",
    "filter-help",
    "AAA",
    "AA",
    "slice=",
    "zP=",
    "oF=",
    "recipe=",
    "dump-recipe=",
    "req-delay=",
    "conn-delay=",
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
    "ntlm=",
    "basic=",
    "digest=",
    "follow",
    "script-help=",
    "script=",
    "script-args=",
    "prefilter=",
    "filter=",
    "interact",
    "help",
    "version",
    "dry-run",
    "prev",
]
REPEATABLE_OPTS = [
    "--efield",
    "--field",
    "--prefilter",
    "--recipe",
    "-z",
    "--zP",
    "--zD",
    "--slice",
    "payload",
    "-w",
    "-b",
    "-H",
    "-p",
]


class CLParser:
    def __init__(
        self,
        argv,
        short_opts=short_opts,
        long_opts=long_opts,
        help_banner=help_banner,
        brief_usage=brief_usage,
        verbose_usage=verbose_usage,
        usage=usage,
    ):
        self.argv = argv
        self.short_opts = short_opts
        self.long_opts = long_opts
        self.help_banner = help_banner
        self.brief_usage = brief_usage
        self.verbose_usage = verbose_usage
        self.usage = usage

    def show_brief_usage(self):
        print(self.help_banner)
        print(self.brief_usage)

    def show_verbose_usage(self):
        print(self.help_banner)
        print(self.verbose_usage)

    def show_usage(self):
        print(self.help_banner)
        print(self.usage)

    def show_plugins_help(self, registrant, cols=3, category="$all$"):
        print("\nAvailable %s:\n" % registrant)
        table_print(
            [x[cols:] for x in Facade().proxy(registrant).get_plugins_ext(category)]
        )
        sys.exit(0)

    def show_plugins_names(self, registrant):
        print("\n".join(Facade().proxy(registrant).get_plugins_names("$all$")))

    def show_plugin_ext_help(self, registrant, category="$all$"):
        for plugin in Facade().proxy(registrant).get_plugins(category):
            print("Name: %s %s" % (plugin.name, plugin.version))
            print("Categories: %s" % ",".join(plugin.category))
            print("Summary: %s" % plugin.summary)
            print("Author: %s" % ",".join(plugin.author))
            print("Description:")
            for desc_lines in plugin.description:
                print("   %s" % desc_lines)
            print("Parameters:")
            for param in plugin.parameters:
                print(
                    "   %s %s%s: %s"
                    % (
                        "+" if param[2] else "-",
                        param[0],
                        " (= %s)" % str(param[1]) if param[1] else "",
                        param[3],
                    )
                )
            print("\n")

        sys.exit(0)

    def parse_cl(self):
        # Usage and command line help
        try:
            opts, args = getopt.getopt(self.argv[1:], self.short_opts, self.long_opts)
            optsd = defaultdict(list)

            payload_cache = {}
            for i, j in opts:
                if i in ["-z", "--zP", "--slice", "-w", "--zD", "--zE"]:
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

            cli_url = None
            if "-u" in optsd:
                if (url is not None and url != "FUZZ") or url == optsd["-u"][0]:
                    raise FuzzExceptBadOptions(
                        "Specify the URL either with -u or last argument. If you want to use a full payload, it can only be specified with FUZZ."
                    )

                cli_url = optsd["-u"][0]

            if cli_url:
                url = cli_url

            # check command line options correctness
            self._check_options(optsd)

            # parse options from recipe first
            if "--recipe" in optsd:
                for recipe in optsd["--recipe"]:
                    options.import_from_file(recipe)

            # command line has priority over recipe
            self._parse_options(optsd, options)
            self._parse_conn_options(optsd, options)
            self._parse_filters(optsd, options)
            self._parse_seed(url, optsd, options)
            self._parse_payload(optsd, options)
            self._parse_scripts(optsd, options)

            if "--dump-recipe" in optsd:
                print(exec_banner)

                for error_msg in options.validate():
                    warnings.warn("Recipe parsing error: {}".format(error_msg))

                print("")

                options.export_to_file(optsd["--dump-recipe"][0])
                print("Recipe written to %s." % (optsd["--dump-recipe"][0],))
                sys.exit(0)

            return options
        except FuzzException as e:
            self.show_brief_usage()
            raise e
        except ValueError:
            self.show_brief_usage()
            raise FuzzExceptBadOptions("Incorrect options, please check help.")
        except getopt.GetoptError as qw:
            self.show_brief_usage()
            raise FuzzExceptBadOptions("%s." % str(qw))

    def _parse_help_opt(self, optsd):
        if "--version" in optsd:
            print(version)
            sys.exit(0)

        if "-h" in optsd:
            self.show_usage()
            sys.exit(0)

        if "--help" in optsd:
            self.show_verbose_usage()
            sys.exit(0)

        if "--filter-help" in optsd:
            FILTER_HELP_REGEX_EXP = (
                "Filter Language\n---------------\n\n(.*?)Filtering results"
            )
            FILTER_HELP_REGEX = re.compile(
                FILTER_HELP_REGEX_EXP, re.MULTILINE | re.DOTALL
            )

            print(FILTER_HELP_REGEX.search(get_filter_help_file()).group(1))

            sys.exit(0)

        # Extensions help
        if "--script-help" in optsd:
            script_string = optsd["--script-help"][0]
            if script_string == "":
                script_string = "$all$"

            self.show_plugin_ext_help("scripts", category=script_string)

        if "--ee" in optsd:
            if "payloads" in optsd["--ee"]:
                self.show_plugins_names("payloads")
            elif "encoders" in optsd["--ee"]:
                self.show_plugins_names("encoders")
            elif "iterators" in optsd["--ee"]:
                self.show_plugins_names("iterators")
            elif "printers" in optsd["--ee"]:
                self.show_plugins_names("printers")
            elif "scripts" in optsd["--ee"]:
                self.show_plugins_names("scripts")
            elif "fields" in optsd["--ee"]:
                print("\n".join(allowed_fields))
            elif "files" in optsd["--ee"]:
                print("\n".join(Facade().sett.get("general", "lookup_dirs").split(",")))
            elif "registrants" in optsd["--ee"]:
                print("\n".join(Facade().get_registrants()))
            elif "options" in optsd["--ee"]:
                print(
                    "\n".join(
                        ["-{}".format(opt) for opt in self.short_opts.replace(":", "")]
                    )
                )
                print(
                    "\n".join(
                        ["--{}".format(opt.replace("=", "")) for opt in self.long_opts]
                    )
                )
            else:
                raise FuzzExceptBadOptions(
                    "Unknown category. Valid values are: payloads, encoders, iterators, printers or scripts."
                )
            sys.exit(0)

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
                raise FuzzExceptBadOptions(
                    "Unknown category. Valid values are: payloads, encoders, iterators, printers or scripts."
                )

        if "-f" in optsd:
            if "help" in optsd["-f"]:
                self.show_plugins_help("printers")
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
        opt_list = [i for i in optsd if i not in REPEATABLE_OPTS and len(optsd[i]) > 1]
        if opt_list:
            raise FuzzExceptBadOptions(
                "Bad usage: Only one %s option could be specified at the same time."
                % " ".join(opt_list)
            )

        # -A and script not allowed at the same time
        if "--script" in list(optsd.keys()) and [
            key for key in optsd.keys() if key in ["-A", "--AA", "--AAA"]
        ]:
            raise FuzzExceptBadOptions(
                "Bad usage: --scripts and -A, --AA, --AAA are incompatible options."
            )

        if "-s" in list(optsd.keys()) and "-t" in list(optsd.keys()):
            warnings.warn(
                "When using delayed requests concurrent requests are limited to 1, therefore the -s switch will be ignored."
            )

    def _parse_filters(self, optsd, filter_params):
        """
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
        """

        if "--prefilter" in optsd:
            if not PYPARSING:
                raise FuzzExceptBadInstall("--prefilter switch needs pyparsing module.")

            for prefilter_opt in optsd["--prefilter"]:
                filter_params["prefilter"].append(prefilter_opt)

        if "--filter" in optsd:
            if not PYPARSING:
                raise FuzzExceptBadInstall("--filter switch needs pyparsing module.")
            filter_params["filter"] = optsd["--filter"][0]

        if "--hc" in optsd:
            filter_params["hc"] = optsd["--hc"][0].split(",")
        if "--hw" in optsd:
            filter_params["hw"] = optsd["--hw"][0].split(",")
        if "--hl" in optsd:
            filter_params["hl"] = optsd["--hl"][0].split(",")
        if "--hh" in optsd:
            filter_params["hh"] = optsd["--hh"][0].split(",")
        if "--hs" in optsd:
            filter_params["hs"] = optsd["--hs"][0]
        if "--sc" in optsd:
            filter_params["sc"] = optsd["--sc"][0].split(",")
        if "--sw" in optsd:
            filter_params["sw"] = optsd["--sw"][0].split(",")
        if "--sl" in optsd:
            filter_params["sl"] = optsd["--sl"][0].split(",")
        if "--sh" in optsd:
            filter_params["sh"] = optsd["--sh"][0].split(",")
        if "--ss" in optsd:
            filter_params["ss"] = optsd["--ss"][0]

    def _parse_payload(self, optsd, options):
        """
        options = dict(
            payloads = [],
            iterator = None,
        )
        """

        payloads_list = []

        for payload in optsd["payload"]:
            if "-z" not in payload and "-w" not in payload:
                raise FuzzExceptBadOptions(
                    "--zP and --slice must be preceded by a -z or -w switch."
                )

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

            default_param_cli = payload["--zD"] if "--zD" in payload else None
            if default_param_cli and default_param:
                raise FuzzExceptBadOptions("--zD and -z parameters are exclusive.")
            elif default_param_cli:
                default_param = default_param_cli

            if extraparams:
                params = dict([x.split("=", 1) for x in extraparams.split(",")])
            if default_param:
                params["default"] = default_param

            encoders = vals[2] if len(vals) == 3 else None
            encoders_cli = payload["--zE"] if "--zE" in payload else None
            if encoders_cli and encoders:
                raise FuzzExceptBadOptions("--zE and -z encoders are exclusive.")
            elif encoders_cli:
                encoders = encoders_cli

            if encoders:
                params["encoder"] = encoders.split("-")
            elif "encoder" in params:
                params["encoder"] = params["encoder"].split("-")
            else:
                params["encoder"] = None

            payloads_list.append((name, params, sliceit))

        if "-m" in optsd:
            options["iterator"] = optsd["-m"][0]

        if payloads_list:
            options["payloads"] = payloads_list

    def _parse_seed(self, url, optsd, options):
        if url:
            options["url"] = url

        if "-X" in optsd:
            options["method"] = optsd["-X"][0]

        if "--basic" in optsd:
            options["auth"] = {"method": "basic", "credentials": optsd["--basic"][0]}

        if "--digest" in optsd:
            options["auth"] = {"method": "digest", "credentials": optsd["--digest"][0]}

        if "--ntlm" in optsd:
            options["auth"] = {"method": "ntlm", "credentials": optsd["--ntlm"][0]}

        if "--follow" in optsd or "-L" in optsd:
            options["follow"] = True

        if "--field" in optsd:
            for field in optsd["--field"]:
                options["fields"].append(field)
            options["show_field"] = True
        elif "--efield" in optsd:
            for field in optsd["--efield"]:
                options["fields"].append(field)

            options["show_field"] = False
        else:
            options["show_field"] = None

        if "--ip" in optsd:
            splitted = optsd["--ip"][0].partition(":")
            if not splitted[0]:
                raise FuzzExceptBadOptions("An IP must be specified")

            options["connect_to_ip"] = {
                "ip": splitted[0],
                "port": splitted[2] if splitted[2] else "80",
            }

        if "-d" in optsd:
            options["postdata"] = optsd["-d"][0]

        for bb in optsd["-b"]:
            options["cookie"].append(bb)

        for x in optsd["-H"]:
            splitted = x.partition(":")
            if splitted[1] != ":":
                raise FuzzExceptBadOptions(
                    'Wrong header specified, it should be in the format "name: value".'
                )
            options["headers"].append((splitted[0], splitted[2].strip()))

        if "-V" in optsd:
            options["allvars"] = str(optsd["-V"][0])

    def _parse_conn_options(self, optsd, conn_options):
        if "-p" in optsd:
            proxy = []

            for p in optsd["-p"]:
                vals = p.split(":")

                if len(vals) == 2:
                    proxy.append((vals[0], vals[1], "HTTP"))
                elif len(vals) == 3:
                    proxy.append((vals[0], vals[1], vals[2]))
                else:
                    raise FuzzExceptBadOptions("Bad proxy parameter specified.")

            conn_options["proxies"] = proxy

        if "--conn-delay" in optsd:
            conn_options["conn_delay"] = int(optsd["--conn-delay"][0])

        if "--req-delay" in optsd:
            conn_options["req_delay"] = int(optsd["--req-delay"][0])

        if "-R" in optsd:
            conn_options["rlevel"] = int(optsd["-R"][0])

        if "-D" in optsd:
            conn_options["dlevel"] = int(optsd["-D"][0])

        if "-Z" in optsd:
            conn_options["scanmode"] = True

        if "-s" in optsd:
            conn_options["delay"] = float(optsd["-s"][0])

        if "-t" in optsd:
            conn_options["concurrent"] = int(optsd["-t"][0])

    def _parse_options(self, optsd, options):
        if "--oF" in optsd:
            options["save"] = optsd["--oF"][0]

        if "-v" in optsd:
            options["verbose"] = True

        if "--prev" in optsd:
            options["previous"] = True

        if "--no-cache" in optsd:
            options["no_cache"] = True

        if "-c" in optsd:
            options["colour"] = True

        if [key for key in optsd.keys() if key in ["-A", "--AA", "--AAA"]]:
            options["verbose"] = True
            options["colour"] = True

        if "-f" in optsd:
            vals = optsd["-f"][0].split(",", 1)

            if len(vals) == 1:
                options["printer"] = (vals[0], None)
            else:
                options["printer"] = vals

        if "-o" in optsd:
            options["console_printer"] = optsd["-o"][0]

        if "--recipe" in optsd:
            options["recipe"] = optsd["--recipe"]

        if "--dry-run" in optsd:
            options["transport"] = "dryrun"

        if "--interact" in optsd:
            options["interactive"] = True

    def _parse_scripts(self, optsd, options):
        """
        options = dict(
            script = "",
            script_args = {},
        )
        """

        if "-A" in optsd:
            options["script"] = "default"

        if "--AA" in optsd:
            options["script"] = "default,verbose"

        if "--AAA" in optsd:
            options["script"] = "default,discovery,verbose"

        if "--script" in optsd:
            options["script"] = (
                "default" if optsd["--script"][0] == "" else optsd["--script"][0]
            )

        if "--script-args" in optsd:
            try:
                options["script_args"] = dict(
                    [x.split("=", 1) for x in optsd["--script-args"][0].split(",")]
                )
            except ValueError:
                raise FuzzExceptBadOptions(
                    "Script arguments: Incorrect arguments format supplied."
                )
