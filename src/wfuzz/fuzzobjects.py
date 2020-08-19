import time
import hashlib
import re
import itertools
from enum import Enum

from threading import Lock
from collections import defaultdict, namedtuple

from .filters.ppfilter import FuzzResFilter
from .facade import ERROR_CODE

from .helpers.str_func import python2_3_convert_to_unicode
from .helpers.obj_dyn import rgetattr
from .helpers.utils import MyCounter


FuzzWord = namedtuple("FuzzWord", ["content", "type"])


class FuzzWordType(Enum):
    WORD, FUZZRES = range(2)


class FuzzType(Enum):
    (
        SEED,
        BACKFEED,
        RESULT,
        ERROR,
        STARTSEED,
        ENDSEED,
        CANCEL,
        DISCARDED,
        PLUGIN,
    ) = range(9)


class FuzzItem(object):
    newid = itertools.count(0)

    def __init__(self, item_type):
        self.item_id = next(FuzzItem.newid)
        self.item_type = item_type

    def __str__(self):
        return "FuzzItem, type: {}".format(self.item_type.name)

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
    def from_options(options):
        tmp_stats = FuzzStats()

        tmp_stats.url = options["compiled_seed"].history.redirect_url
        tmp_stats.total_req = options["compiled_dictio"].count()
        tmp_stats.seed = options["compiled_seed"]

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
            string += "Processed Requests: %s (%d + %d)\n" % (
                str(self.processed())[:8],
                (self.processed() - self.backfeed()),
                self.backfeed(),
            )
        else:
            string += "Processed Requests: %s\n" % (str(self.processed())[:8])
        string += "Filtered Requests: %s\n" % (str(self.filtered())[:8])
        string += (
            "Requests/sec.: %s\n"
            % str(self.processed() / self.totaltime if self.totaltime > 0 else 0)[:8]
        )

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


class FuzzPayload:
    def __init__(self):
        self.marker = None
        self.word = None
        self.index = None
        self.field = None
        self.content = None
        self.is_baseline = False
        self.type = None

    @property
    def value(self):
        if self.content is None:
            return None
        return (
            self.content
            if self.field is None
            else str(rgetattr(self.content, self.field))
        )

    def description(self, default):
        if self.is_baseline:
            return self.content

        if self.marker is None:
            return ""

        if self.field is None and isinstance(self.content, FuzzResult):
            return rgetattr(self.content, default)
        elif self.field is not None and isinstance(self.content, FuzzResult):
            return str(rgetattr(self.content, self.field))

        return self.value

    def __str__(self):
        return "type: {} index: {} marker: {} content: {} field: {} value: {}".format(
            self.type,
            self.index,
            self.marker,
            self.content.__class__,
            self.field,
            self.value,
        )


class FPayloadManager:
    def __init__(self):
        self.payloads = defaultdict(list)

    def add(self, payload_dict, fuzzword=None, is_baseline=False):
        fp = FuzzPayload()
        fp.marker = payload_dict["full_marker"]
        fp.word = payload_dict["word"]
        fp.index = (
            int(payload_dict["index"]) if payload_dict["index"] is not None else 1
        )
        fp.field = payload_dict["field"]
        fp.content = fuzzword.content if fuzzword else None
        fp.type = fuzzword.type if fuzzword else None
        fp.is_baseline = is_baseline

        self.payloads[fp.index].append(fp)

    def update_from_dictio(self, dictio_item):
        for index, dictio_payload in enumerate(dictio_item, 1):
            fuzz_payload = None
            for fuzz_payload in self.payloads[index]:
                fuzz_payload.content = dictio_payload.content
                fuzz_payload.type = dictio_payload.type

            # payload generated not used in seed but in filters
            if fuzz_payload is None:
                self.add(
                    {"full_marker": None, "word": None, "index": index, "field": None},
                    dictio_item[index - 1],
                )

    def get_fuzz_words(self):
        return [payload.word for payload in self.get_payloads()]

    def get_payload(self, index):
        return self.payloads[index]

    def get_payload_type(self, index):
        return self.get_payload(index)[0].type

    def get_payload_content(self, index):
        return self.get_payload(index)[0].content

    def get_payloads(self):
        for index, elem_list in sorted(self.payloads.items()):
            for elem in elem_list:
                yield elem

    def description(self):
        payl_descriptions = [
            payload.description("url") for payload in self.get_payloads()
        ]
        ret_str = " - ".join([p_des for p_des in payl_descriptions if p_des])

        return ret_str

    def __str__(self):
        return "\n".join([str(payload) for payload in self.get_payloads()])


class FuzzError(FuzzItem):
    def __init__(self, exception):
        FuzzItem.__init__(self, FuzzType.ERROR)
        self.exception = exception


class FuzzResult(FuzzItem):
    newid = itertools.count(0)
    FUZZRESULT_SHARED_FILTER = FuzzResFilter()

    def __init__(self, history=None, exception=None, track_id=True):
        FuzzItem.__init__(self, FuzzType.RESULT)
        self.history = history

        self.exception = exception
        self.is_baseline = False
        self.rlevel = 1
        self.rlevel_desc = ""
        self.nres = next(FuzzResult.newid) if track_id else 0

        self.chars = 0
        self.lines = 0
        self.words = 0
        self.md5 = ""

        self.update()

        self.plugins_res = []

        self.payload_man = None

        self._fields = None
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
        res = '%05d:  C=%03d   %4d L\t   %5d W\t  %5d Ch\t  "%s"' % (
            self.nres,
            self.code,
            self.lines,
            self.words,
            self.chars,
            self.description,
        )
        for plugin in self.plugins_res:
            res += "\n  |_ %s" % plugin.issue

        return res

    @property
    def description(self):
        res_description = (
            self.payload_man.description() if self.payload_man else self.url
        )
        ret_str = ""

        if self._show_field is True:
            ret_str = self._field()
        elif self._show_field is False and self._fields is not None:
            ret_str = "{} | {}".format(res_description, self._field())
        else:
            ret_str = res_description

        if not ret_str:
            ret_str = self.url

        if self.exception:
            return ret_str + "! " + str(self.exception)

        if self.rlevel > 1:
            return self.rlevel_desc + " - " + ret_str

        return ret_str

    def eval(self, expr):
        return self.FUZZRESULT_SHARED_FILTER.is_visible(self, expr)

    def _field(self):
        return " | ".join([str(self.eval(field)) for field in self._fields])

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

    def update_from_options(self, options):
        self._fields = options["fields"]
        self._show_field = options["show_field"]


class FuzzPlugin(FuzzItem):
    def __init__(self):
        FuzzItem.__init__(self, FuzzType.PLUGIN)
        self.source = ""
        self.issue = ""
        self._exception = None
        self._seed = None
