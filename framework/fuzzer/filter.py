from framework.core.myexception import FuzzException
from threading import Thread

from framework.fuzzer.fuzzobjects import FuzzResult
from framework.utils.myqueue import FuzzQueue
from framework.plugins.api.urlutils import parse_res, parse_url

import re
import urlparse

PYPARSING = True
try:
    from  pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal, alphanums, Or, OneOrMore, QuotedString, printables
    from  pyparsing import ParseException
except ImportError:
    PYPARSING = False


class FuzzResFilter:
    def __init__(self, ffilter = None):
	if PYPARSING:
	    element = oneOf("c l w h index")
	    adv_element = oneOf("intext inurl site inheader filetype")
	    adv_element_bool = oneOf("hasquery ispath")
	    digits = "XB0123456789"
	    integer = Word( digits )#.setParseAction( self.__convertIntegers )
	    elementRef = Group(element + oneOf("= != < > >= <=") + integer)
	    adv_elementRef = Group(adv_element + oneOf("= !=") + QuotedString('\'', unquoteResults=True, escChar='\\'))
	    operator = oneOf("and or")
	    not_operator = oneOf("not")
	    adv_elementRef_bool = Group(Optional(not_operator, "notpresent") + adv_element_bool)
	    definition = adv_elementRef ^ elementRef ^ adv_elementRef_bool + ZeroOrMore( operator + adv_elementRef ^ adv_elementRef_bool ^ elementRef)
	    nestedformula = Group(Suppress(Optional(Literal("("))) + definition + Suppress(Optional(Literal(")"))))
	    self.finalformula = nestedformula + ZeroOrMore( operator + nestedformula)

	    elementRef.setParseAction(self.__compute_element)
	    adv_elementRef.setParseAction(self.__compute_adv_element)
	    adv_elementRef_bool.setParseAction(self.__compute_adv_element_bool)
	    nestedformula.setParseAction(self.__compute_formula)
	    self.finalformula.setParseAction(self.__myreduce)

	self.res = None
        if ffilter:
            self.hideparams = ffilter
        else:
            self.hideparams = dict(
                regex_show = None,
                codes_show = None,
                codes = [],
                words = [],
                lines = [],
                chars = [],
                regex = None,
                filter_string = ""
                )

	if "XXX" in self.hideparams['codes']:
	    self.hideparams['codes'].append("0")

	self.baseline = None

    def set_baseline(self, res):
	if "BBB" in self.hideparams['lines']:
	    self.hideparams['lines'].append(str(res.lines))
	if "BBB" in self.hideparams['codes']:
	    self.hideparams['codes'].append(str(res.code))
	if "BBB" in self.hideparams['words']:
	    self.hideparams['words'].append(str(res.words))
	if "BBB" in self.hideparams['chars']:
	    self.hideparams['chars'].append(str(res.chars))

	self.baseline = res

    def __convertIntegers(self, tokens):
	return int(tokens[0])

    def __compute_adv_element_bool(self, tokens):
	operator, adv_element = tokens[0]

	cond = False

	if adv_element == 'hasquery':
	    if urlparse.urlparse(self.res.url).query:
		cond = True
	elif adv_element == 'ispath':
		cond = self.res.history.is_path

	return cond if operator == "notpresent" else not cond

    def __compute_adv_element(self, tokens):
	adv_element, operator, value = tokens[0]

	cond = False

	if adv_element == 'intext':
	    regex = re.compile(value, re.MULTILINE|re.DOTALL)
	    cond = False
	    if regex.search(self.res.history.content): cond = True
	elif adv_element == 'inurl':
	    regex = re.compile(value, re.MULTILINE|re.DOTALL)
	    cond = False
	    if regex.search(self.res.url): cond = True
	elif adv_element == 'filetype':
	    if parse_res(self.res).file_extension == value:
		cond = True
	elif adv_element == 'site':
	    if urlparse.urlparse(self.res.url).netloc.rfind(value) >= 0:
		cond = True
	elif adv_element == 'inheader':
	    regex = re.compile(value, re.MULTILINE|re.DOTALL)
	    cond = False
	    
	    if regex.search("\n".join([': '.join(k) for k in self.res.history.headers.response.items()])): cond = True

	return cond if operator == "=" else not cond

    def __compute_element(self, tokens):
	element, operator, value = tokens[0]
	
	if value == 'BBB' and self.baseline == None:
	    raise FuzzException(FuzzException.FATAL, "FilterQ: specify a baseline value when using BBB")

	if element == 'c' and value == 'XXX':
	    value = 0

	if value == 'BBB':
	    if element == 'l':
		value = self.baseline.lines
	    elif element == 'c':
		value = self.baseline.code
	    elif element == 'w':
		value = self.baseline.words
	    elif element == 'h':
		value = self.baseline.chars
	    elif element == 'index':
		value = self.baseline.nres

	test = dict(w=self.res.words, c=self.res.code, l=self.res.lines, h=self.res.chars, index=self.res.nres)
	value = int(value)

	if operator == "=":
	    return test[element] == value
	elif operator == "<=":
	    return test[element] <= value
	elif operator == ">=":
	    return test[element] >= value
	elif operator == "<":
	    return test[element] < value
	elif operator == ">":
	    return test[element] > value
	elif operator == "!=":
	    return test[element] != value

    def __myreduce(self, elements):
	first = elements[0]
	for i in range(1, len(elements), 2):
	    if elements[i] == "and":
		first = (first and elements[i+1])
	    elif elements[i] == "or":
		first = (first or elements[i+1])

	return first

    def __compute_formula(self, tokens):
	return self.__myreduce(tokens[0])

    def is_active(self):
	return any([
            self.hideparams['regex_show'] is not None,
            self.hideparams['codes_show'] is not None,
            self.hideparams['filter_string'] != "",
        ])

    def is_visible(self, res):
	# baseline
	if self.baseline and res.is_baseline == True:
	    return True

	filter_string = self.hideparams['filter_string']
	if filter_string and PYPARSING:
	    self.res = res
	    try:
		return self.finalformula.parseString(filter_string)[0]
	    except ParseException, e:
		raise FuzzException(FuzzException.FATAL, "Incorrect filter expression. It should be composed of: c,l,w,h,intext,inurl,site,inheader,filetype,ispath,hasquery;not,and,or;=,<,>,!=,<=,>=")
	else:
	    if self.baseline == None and ('BBB' in self.hideparams['codes'] \
		    or 'BBB' in self.hideparams['lines'] \
		    or 'BBB' in self.hideparams['words'] \
		    or 'BBB' in self.hideparams['chars']):
			raise FuzzException(FuzzException.FATAL, "FilterQ: specify a baseline value when using BBB")

	    if self.hideparams['codes_show'] is None:
		cond1 = True
	    else:
		cond1 = not self.hideparams['codes_show']

	    if self.hideparams['regex_show'] is None:
		cond2 = True
	    else:
		cond2 = not self.hideparams['regex_show']

	    if str(res.code) in self.hideparams['codes'] \
		or str(res.lines) in self.hideparams['lines'] \
		or str(res.words) in self.hideparams['words'] \
		or str(res.chars) in self.hideparams['chars']:
		    cond1 = self.hideparams['codes_show']

	    if self.hideparams['regex']:
		if self.hideparams['regex'].search(res.history.content):
		    cond2 = self.hideparams['regex_show']

	    return (cond1 and cond2)

    @staticmethod
    def from_options(filter_options):
        ffilter = FuzzResFilter()

	ffilter.hideparams["filter_string"] = filter_options["filterstr"]

	try:
	    if filter_options["ss"] is not None:
		ffilter.hideparams['regex_show'] = True
		ffilter.hideparams['regex'] = re.compile(filter_options['ss'], re.MULTILINE|re.DOTALL)

	    elif filter_options["hs"] is not None:
		ffilter.hideparams['regex_show'] = False
		ffilter.hideparams['regex'] = re.compile(filter_options['hs'], re.MULTILINE|re.DOTALL)
	except Exception, e:
	    raise FuzzException(FuzzException.FATAL, "Invalied regex expression: %s" % str(e))

	if filter(lambda x: len(filter_options[x]) > 0, ["sc", "sw", "sh", "sl"]):
	    ffilter.hideparams['codes_show'] = True
	    ffilter.hideparams['codes'] = filter_options["sc"]
	    ffilter.hideparams['words'] = filter_options["sw"]
	    ffilter.hideparams['lines'] = filter_options["sl"]
	    ffilter.hideparams['chars'] = filter_options["sh"]
	elif filter(lambda x: len(filter_options[x]) > 0, ["hc", "hw", "hh", "hl"]):
	    ffilter.hideparams['codes_show'] = False
	    ffilter.hideparams['codes'] = filter_options["hc"]
	    ffilter.hideparams['words'] = filter_options["hw"]
	    ffilter.hideparams['lines'] = filter_options["hl"]
	    ffilter.hideparams['chars'] = filter_options["hh"]

        return ffilter

class FilterQ(FuzzQueue):
    def __init__(self, ffilter, queue_out):
	FuzzQueue.__init__(self, queue_out)
	Thread.__init__(self)

	self.setName('filter_thread')

	self.queue_out = queue_out
	self.ffilter = ffilter

    def get_name(self):
	return 'filter_thread'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if item.is_baseline:
	    self.ffilter.set_baseline(item)
	item.is_visible = self.ffilter.is_visible(item)
	self.send(item)

if __name__ == "__main__":
    tests = []
    tests.append("(w=200 and w=200) or w=200")
    tests.append("(w=400 and w=200) and (w=200 or w=200 or w=000)")
    tests.append("(w=200 and l=7) and (h=23)")
    tests.append("w=201")
    tests.append("w=200")

    class t:
	code = 200
	words = 200
	lines = 7
	chars = 23

    res = t()

    f = FilterQ()
    for i in tests:
	print "%s := %s" % (str(i), f.is_visible(res, i))
