import time
import hashlib
import re
import itertools
import operator
from enum import Enum

from threading import Lock
from collections import namedtuple
from collections import defaultdict

from .fuzzrequest import FuzzRequest
from .filter import FuzzResFilter
from .exception import FuzzExceptBadOptions, FuzzExceptInternalError
from .facade import ERROR_CODE

from .utils import python2_3_convert_to_unicode
from .utils import MyCounter
from .utils import rgetattr

auth_header = namedtuple("auth_header", "method credentials")


class FuzzType(Enum):
    SEED, BACKFEED, RESULT, ERROR, STARTSEED, ENDSEED, CANCEL, DISCARDED = range(8)


class FuzzItem(object):
    newid = itertools.count(0)

    def __init__(self, item_type):
        self.item_id = next(FuzzItem.newid)
        self.item_type = item_type

    def __str__(self):
        return "FuzzItem, type: {}".format(self.item_type.name)

    def get_type(self):
        raise NotImplementedError

    def __lt__(self, other):
        return self.item_id < other.item_id

    def __le__(self, other):
        return self.item_id <= other.item_id

    def __gt__(self, other):
        return self.item_id > other.item_id

    def __ge__(self, other):
        return self.item_id >= other.item_id

    def __eq__(self, other):
        return self.item_id == other.item_id

    def __ne__(self, other):
        return self.item_id != other.item_id


class FuzzResultFactory:
    @staticmethod
    def replace_fuzz_word(text, fuzz_word, payload):
        marker_regex = re.compile(r"(%s)(?:\[(.*?)\])?" % (fuzz_word,), re.MULTILINE | re.DOTALL)

        for fuzz_word, field in marker_regex.findall(text):
            if field:
                marker_regex = re.compile(r"(%s)(?:\[(.*?)\])?" % (fuzz_word,), re.MULTILINE | re.DOTALL)
                fields_array = []

                for fuzz_word, field in marker_regex.findall(text):
                    if not field:
                        raise FuzzExceptBadOptions("You must specify a field when using a payload containing a full fuzz request, ie. FUZZ[url], or use FUZZ only to repeat the same request.")

                    try:
                        subs = str(rgetattr(payload, field))
                    except AttributeError:
                        raise FuzzExceptBadOptions("A FUZZ[field] expression must be used with a fuzzresult payload not a string.")

                    text = text.replace("%s[%s]" % (fuzz_word, field), subs)
                    fields_array.append(field)

                return (text, fields_array)
            else:
                try:
                    return (text.replace(fuzz_word, payload), [None])
                except TypeError:
                    raise FuzzExceptBadOptions("Tried to replace {} with a whole fuzzresult payload.".format(fuzz_word))

    @staticmethod
    def from_seed(seed, payload, seed_options):
        newres = seed.from_soft_copy()

        rawReq = str(newres.history)
        rawUrl = newres.history.redirect_url
        scheme = newres.history.scheme
        auth_method, userpass = newres.history.auth

        for payload_pos, payload_content in enumerate(payload, start=1):
            fuzz_word = "FUZ" + str(payload_pos) + "Z" if payload_pos > 1 else "FUZZ"

            fuzz_values_array = []

            # substitute entire seed when using a request payload generator without specifying field
            if fuzz_word == "FUZZ" and seed_options["seed_payload"] and isinstance(payload_content, FuzzResult):
                # new seed
                newres = payload_content.from_soft_copy()
                newres.payload = []

                fuzz_values_array.append(None)

                newres.history.update_from_options(seed_options)
                newres.update_from_options(seed_options)
                rawReq = str(newres.history)
                rawUrl = newres.history.redirect_url
                scheme = newres.history.scheme
                auth_method, userpass = newres.history.auth

            desc = []

            if auth_method and (userpass.count(fuzz_word)):
                userpass, desc = FuzzResultFactory.replace_fuzz_word(userpass, fuzz_word, payload_content)
            if newres.history.redirect_url.count(fuzz_word):
                rawUrl, desc = FuzzResultFactory.replace_fuzz_word(rawUrl, fuzz_word, payload_content)
            if rawReq.count(fuzz_word):
                rawReq, desc = FuzzResultFactory.replace_fuzz_word(rawReq, fuzz_word, payload_content)

            if scheme.count(fuzz_word):
                scheme, desc = FuzzResultFactory.replace_fuzz_word(scheme, fuzz_word, payload_content)

            if desc:
                fuzz_values_array += desc

            newres.payload.append(FuzzPayload(payload_content, fuzz_values_array))

        newres.history.update_from_raw_http(rawReq, scheme)
        newres.history.url = rawUrl
        if auth_method != 'None':
            newres.history.auth = (auth_method, userpass)

        return newres

    @staticmethod
    def from_baseline(fuzzresult, options):
        scheme = fuzzresult.history.scheme
        rawReq = str(fuzzresult.history)
        auth_method, userpass = fuzzresult.history.auth

        # get the baseline payload ordered by fuzz number and only one value per same fuzz keyword.
        b1 = dict([matchgroup.groups() for matchgroup in re.finditer(r"FUZ(\d*)Z(?:\[.*?\])?(?:{(.*?)})?", rawReq, re.MULTILINE | re.DOTALL)])
        b2 = dict([matchgroup.groups() for matchgroup in re.finditer(r"FUZ(\d*)Z(?:\[.*?\])?(?:{(.*?)})?", userpass, re.MULTILINE | re.DOTALL)])
        baseline_control = dict(list(b1.items()) + list(b2.items()))
        baseline_payload = [x[1] for x in sorted(list(baseline_control.items()), key=operator.itemgetter(0))]

        # if there is no marker, there is no baseline request
        if not [x for x in baseline_payload if x is not None]:
            return None

        # remove baseline marker from seed request
        for i in baseline_payload:
            if not i:
                raise FuzzExceptBadOptions("You must supply a baseline value for all the FUZZ words.")
            rawReq = rawReq.replace("{" + i + "}", '')

            if fuzzresult.history.wf_fuzz_methods:
                fuzzresult.history.wf_fuzz_methods = fuzzresult.history.wf_fuzz_methods.replace("{" + i + "}", '')

            if auth_method:
                userpass = userpass.replace("{" + i + "}", '')

        # re-parse seed without baseline markers
        fuzzresult.history.update_from_raw_http(rawReq, scheme)
        if auth_method:
            fuzzresult.history.auth = (auth_method, userpass)

        # create baseline request from seed
        baseline_res = fuzzresult.from_soft_copy()

        # remove field markers from baseline
        marker_regex = re.compile(r"(FUZ\d*Z)\[(.*?)\]", re.DOTALL)
        results = marker_regex.findall(rawReq)
        if results:
            for fw, f in results:
                rawReq = rawReq.replace("%s[%s]" % (fw, f), fw)

                if fuzzresult.history.wf_fuzz_methods:
                    fuzzresult.history.wf_fuzz_methods = fuzzresult.history.wf_fuzz_methods.replace("{" + i + "}", '')

                if auth_method:
                    userpass = userpass.replace("{" + i + "}", '')

            baseline_res.history.update_from_raw_http(rawReq, scheme)

        baseline_res = FuzzResultFactory.from_seed(baseline_res, baseline_payload, options)
        baseline_res.is_baseline = True

        return baseline_res

    @staticmethod
    def from_options(options):
        fr = FuzzRequest()

        fr.url = options['url']
        fr.wf_fuzz_methods = options['method']
        fr.update_from_options(options)

        fuzz_res = FuzzResult(fr)
        fuzz_res.update_from_options(options)

        return fuzz_res


class FuzzStats:
    def __init__(self):
        self.mutex = Lock()

        self.url = ""
        self.seed = None

        self.total_req = 0
        self.pending_fuzz = MyCounter()
        self.pending_seeds = MyCounter()
        self.processed = MyCounter()
        self.backfeed = MyCounter()
        self.filtered = MyCounter()

        self.totaltime = 0
        self.__starttime = 0

        self._cancelled = False

    @staticmethod
    def from_requestGenerator(rg):
        tmp_stats = FuzzStats()

        tmp_stats.url = rg.seed.history.redirect_url
        tmp_stats.total_req = rg.count()
        tmp_stats.seed = rg.seed

        return tmp_stats

    def get_stats(self):
        return {
            "url": self.url,
            "total": self.total_req,

            "backfed": self.backfeed(),
            "Processed": self.processed(),
            "Pending": self.pending_fuzz(),
            "filtered": self.filtered(),

            "Pending_seeds": self.pending_seeds(),

            "totaltime": self._totaltime,
        }

    def mark_start(self):
        with self.mutex:
            self.__starttime = time.time()

    def mark_end(self):
        with self.mutex:
            self.totaltime = time.time() - self.__starttime

    @property
    def cancelled(self):
        with self.mutex:
            return self._cancelled

    @cancelled.setter
    def cancelled(self, v):
        with self.mutex:
            self._cancelled = v

    def __str__(self):
        string = ""

        string += "Total time: %s\n" % str(self.totaltime)[:8]

        if self.backfeed() > 0:
            string += "Processed Requests: %s (%d + %d)\n" % (str(self.processed())[:8], (self.processed() - self.backfeed()), self.backfeed())
        else:
            string += "Processed Requests: %s\n" % (str(self.processed())[:8])
        string += "Filtered Requests: %s\n" % (str(self.filtered())[:8])
        string += "Requests/sec.: %s\n" % str(self.processed() / self.totaltime if self.totaltime > 0 else 0)[:8]

        return string

    def update(self, fuzzstats2):
        self.url = fuzzstats2.url
        self.total_req += fuzzstats2.total_req
        self.totaltime += fuzzstats2.totaltime

        self.backfeed._operation(fuzzstats2.backfeed())
        self.processed._operation(fuzzstats2.processed())
        self.pending_fuzz._operation(fuzzstats2.pending_fuzz())
        self.filtered._operation(fuzzstats2.filtered())
        self.pending_seeds._operation(fuzzstats2.pending_seeds())


class FuzzPayload():
    def __init__(self, content, fields):
        self.content = content
        self.fields = fields

    def description(self, default):
        ret_str_values = []
        for fuzz_value in self.fields:
            if fuzz_value is None and isinstance(self.content, FuzzResult):
                ret_str_values.append(default)
            elif fuzz_value is not None and isinstance(self.content, FuzzResult):
                ret_str_values.append(str(rgetattr(self.content, fuzz_value)))
            elif fuzz_value is None:
                ret_str_values.append(self.content)
            else:
                ret_str_values.append(fuzz_value)

        return " - ".join(ret_str_values)

    def __str__(self):
        return "content: {} fields: {}".format(self.content, self.fields)


class FuzzError(FuzzItem):
    def __init__(self, exception):
        FuzzItem.__init__(self, FuzzType.ERROR)
        self.exception = exception


class FuzzResult(FuzzItem):
    newid = itertools.count(0)

    def __init__(self, history=None, exception=None, track_id=True):
        FuzzItem.__init__(self, FuzzType.RESULT)
        self.history = history

        self.exception = exception
        self.is_baseline = False
        self.rlevel = 1
        self.nres = next(FuzzResult.newid) if track_id else 0

        self.chars = 0
        self.lines = 0
        self.words = 0
        self.md5 = ""

        self.update()

        self.plugins_res = []
        self.plugins_backfeed = []

        self.payload = []

        self._description = None
        self._show_field = False

    @property
    def plugins(self):
        dic = defaultdict(list)

        for pl in self.plugins_res:
            dic[pl.source].append(pl.issue)

        return dic

    def update(self, exception=None):
        self.item_type = FuzzType.RESULT
        if exception:
            self.exception = exception

        if self.history and self.history.content:
            m = hashlib.md5()
            m.update(python2_3_convert_to_unicode(self.history.content))
            self.md5 = m.hexdigest()

            self.chars = len(self.history.content)
            self.lines = self.history.content.count("\n")
            self.words = len(re.findall(r"\S+", self.history.content))

        return self

    def __str__(self):
        res = "%05d:  C=%03d   %4d L\t   %5d W\t  %5d Ch\t  \"%s\"" % (self.nres, self.code, self.lines, self.words, self.chars, self.description)
        for i in self.plugins_res:
            res += "\n  |_ %s" % i.issue

        return res

    def _payload_description(self):
        if not self.payload:
            return self.url

        payl_descriptions = [payload.description(self.url) for payload in self.payload]
        ret_str = ' - '.join([p_des for p_des in payl_descriptions if p_des])

        return ret_str

    @property
    def description(self):
        ret_str = ""

        if self._show_field is True:
            ret_str = self.eval(self._description)
        elif self._show_field is False and self._description is not None:
            ret_str = "{} | {}".format(self._payload_description(), self.eval(self._description))
        else:
            ret_str = self._payload_description()

        if self.exception:
            return ret_str + "! " + str(self.exception)

        return ret_str

    def eval(self, expr):
        return FuzzResFilter(filter_string=expr).is_visible(self)

    # parameters in common with fuzzrequest
    @property
    def content(self):
        return self.history.content if self.history else ""

    @property
    def url(self):
        return self.history.url if self.history else ""

    @property
    def code(self):
        if self.history and self.history.code >= 0 and not self.exception:
            return int(self.history.code)
        # elif not self.history.code:
            # return 0
        else:
            return ERROR_CODE

    @property
    def timer(self):
        return self.history.reqtime if self.history and self.history.reqtime else 0

    # factory methods

    def to_new_seed(self):
        seed = self.from_soft_copy(False)

        if seed.item_type == FuzzType.ERROR:
            raise FuzzExceptInternalError("A new seed cannot be created with a Fuzz item representing an error.")

        seed.history.url = self.history.recursive_url
        seed.rlevel += 1
        seed.item_type = FuzzType.SEED

        return seed

    def from_soft_copy(self, track_id=True):
        fr = FuzzResult(self.history.from_copy(), track_id=track_id)

        fr.exception = self.exception
        fr.is_baseline = self.is_baseline
        fr.item_type = self.item_type
        fr.rlevel = self.rlevel
        fr.payload = list(self.payload)
        fr._description = self._description
        fr._show_field = self._show_field

        return fr

    def update_from_options(self, options):
        self._description = options['description']
        self._show_field = options['show_field']

    def to_new_url(self, url):
        fr = self.from_soft_copy()
        fr.history.url = str(url)
        fr.rlevel = self.rlevel + 1
        fr.item_type = FuzzType.BACKFEED
        fr.is_baseline = False

        return fr


class PluginItem:
    undefined, result, backfeed = list(range(3))

    def __init__(self, ptype):
        self.source = ""
        self.plugintype = ptype


class PluginResult(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.result)

        self.issue = ""


class PluginRequest(PluginItem):
    def __init__(self):
        PluginItem.__init__(self, PluginItem.backfeed)

        self.fuzzitem = None

    @staticmethod
    def from_fuzzRes(res, url, source):
        plreq = PluginRequest()
        plreq.source = source
        plreq.fuzzitem = res.to_new_url(url)
        plreq.fuzzitem.payload = [FuzzPayload(url, [None])]

        return plreq
