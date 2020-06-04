from ..exception import FuzzExceptBadOptions

import re
import collections

from ..facade import BASELINE_CODE


class FuzzResSimpleFilter:
    def __init__(self, ffilter=None):
        self.hideparams = dict(
            regex_show=None,
            codes_show=None,
            codes=[],
            words=[],
            lines=[],
            chars=[],
            regex=None,
        )

        if ffilter is not None:
            self.hideparams = ffilter

        self.stack = []

        self._cache = collections.defaultdict(set)

    def is_active(self):
        return any(
            [
                self.hideparams["regex_show"] is not None,
                self.hideparams["codes_show"] is not None,
            ]
        )

    def set_baseline(self, res):
        if BASELINE_CODE in self.hideparams["lines"]:
            self.hideparams["lines"].append(res.lines)
        if BASELINE_CODE in self.hideparams["codes"]:
            self.hideparams["codes"].append(res.code)
        if BASELINE_CODE in self.hideparams["words"]:
            self.hideparams["words"].append(res.words)
        if BASELINE_CODE in self.hideparams["chars"]:
            self.hideparams["chars"].append(res.chars)

    def is_visible(self, res):
        if self.hideparams["codes_show"] is None:
            cond1 = True
        else:
            cond1 = not self.hideparams["codes_show"]

        if self.hideparams["regex_show"] is None:
            cond2 = True
        else:
            cond2 = not self.hideparams["regex_show"]

        if (
            res.code in self.hideparams["codes"]
            or res.lines in self.hideparams["lines"]
            or res.words in self.hideparams["words"]
            or res.chars in self.hideparams["chars"]
        ):
            cond1 = self.hideparams["codes_show"]

        if self.hideparams["regex"]:
            if self.hideparams["regex"].search(res.history.content):
                cond2 = self.hideparams["regex_show"]

        return cond1 and cond2

    @staticmethod
    def from_options(filter_options):
        ffilter = FuzzResSimpleFilter()

        try:
            if filter_options["ss"] is not None:
                ffilter.hideparams["regex_show"] = True
                ffilter.hideparams["regex"] = re.compile(
                    filter_options["ss"], re.MULTILINE | re.DOTALL
                )

            elif filter_options["hs"] is not None:
                ffilter.hideparams["regex_show"] = False
                ffilter.hideparams["regex"] = re.compile(
                    filter_options["hs"], re.MULTILINE | re.DOTALL
                )
        except Exception as e:
            raise FuzzExceptBadOptions(
                "Invalid regex expression used in filter: %s" % str(e)
            )

        if [x for x in ["sc", "sw", "sh", "sl"] if len(filter_options[x]) > 0]:
            ffilter.hideparams["codes_show"] = True
            ffilter.hideparams["codes"] = filter_options["sc"]
            ffilter.hideparams["words"] = filter_options["sw"]
            ffilter.hideparams["lines"] = filter_options["sl"]
            ffilter.hideparams["chars"] = filter_options["sh"]
        elif [x for x in ["hc", "hw", "hh", "hl"] if len(filter_options[x]) > 0]:
            ffilter.hideparams["codes_show"] = False
            ffilter.hideparams["codes"] = filter_options["hc"]
            ffilter.hideparams["words"] = filter_options["hw"]
            ffilter.hideparams["lines"] = filter_options["hl"]
            ffilter.hideparams["chars"] = filter_options["hh"]

        return ffilter
