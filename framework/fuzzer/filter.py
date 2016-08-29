from framework.core.myexception import FuzzException
from framework.fuzzobjects import FuzzResult
from threading import Thread

from framework.utils.myqueue import FuzzQueue

import re
import collections


PYPARSING = True
try:
    from  pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal, alphanums, Or, OneOrMore, QuotedString, printables
    from  pyparsing import ParseException
except ImportError:
    PYPARSING = False


class FuzzResFilter:
    def __init__(self, ffilter = None, filter_string = None):
	if PYPARSING:
	    element = oneOf("c code l lines w words h chars i index")
	    adv_element = oneOf("intext inurl site inheader filetype")
	    adv_element_bool = oneOf("hasquery ispath")
            filter_element = Suppress("FUZZ[") + Word( alphanums + "." ) + Suppress(Literal("]"))
            special_element = Suppress("unique(") + filter_element + Suppress(Literal(")"))
            sed_element = Suppress("replace(") + filter_element + Suppress(Literal(",")) + QuotedString('\'', unquoteResults=True, escChar='\\') + Suppress(Literal(",")) + QuotedString('\'', unquoteResults=True, escChar='\\') + Suppress(Literal(")"))
	    digits = "XB0123456789"
	    integer = Word( digits )#.setParseAction( self.__convertIntegers )
	    elementRef = Group(element + oneOf("= != < > >= <=") + integer)
	    adv_elementRef = Group(adv_element + oneOf("= !=") + QuotedString('\'', unquoteResults=True, escChar='\\'))
	    filterRef = Group(filter_element + oneOf("= != ~") + QuotedString('\'', unquoteResults=True, escChar='\\'))
	    operator = oneOf("and or")
	    not_operator = oneOf("not")
	    adv_elementRef_bool = Group(Optional(not_operator, "notpresent") + adv_element_bool)
	    definition = sed_element ^ filterRef ^ adv_elementRef ^ elementRef ^ adv_elementRef_bool ^ special_element + ZeroOrMore( operator + filterRef ^  adv_elementRef ^ adv_elementRef_bool ^ elementRef ^ special_element)
	    nestedformula = Group(Suppress(Optional(Literal("("))) + definition + Suppress(Optional(Literal(")"))))
	    self.finalformula = nestedformula + ZeroOrMore( operator + nestedformula)

	    elementRef.setParseAction(self.__compute_element)
	    adv_elementRef.setParseAction(self.__compute_adv_element)
	    adv_elementRef_bool.setParseAction(self.__compute_adv_element_bool)
	    filterRef.setParseAction(self.__compute_filter_element)
	    sed_element.setParseAction(self.__compute_sed_element)
	    nestedformula.setParseAction(self.__compute_formula)
	    special_element.setParseAction(self.__compute_special_element)
	    self.finalformula.setParseAction(self.__myreduce)

        if ffilter is not None and filter_string is not None:
            raise FuzzException(FuzzException.FATAL, "A filter must be initilized with a filter string or an object, not both")

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

        if filter_string:
            self.hideparams['filter_string'] = filter_string

	if "XXX" in self.hideparams['codes']:
	    self.hideparams['codes'].append(str(FuzzResult.ERROR_CODE))

	self.baseline = None

        self._cache = collections.defaultdict(set)

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

    def __compute_special_element(self, tokens):
	special_element = tokens[0]

        item = self.res.get_field(special_element)

        if item not in self._cache[special_element]:
            self._cache[special_element].add(item)
            return True
        else:
            return False

    def __compute_sed_element(self, tokens):
	field, old, new = tokens

        self.res.set_field(field, self.res.get_field(field).replace(old, new))

        return True


    def __compute_adv_element_bool(self, tokens):
	operator, adv_element = tokens[0]

	cond = False

	if adv_element == 'hasquery':
	    if self.res.history.urlparse.query:
		cond = True

    def __compute_filter_element(self, tokens):
	filter_element, operator, value = tokens[0]

        leftvalue = self.res.get_field(filter_element)
	cond = False

	if operator == "=":
	    return value == leftvalue
	elif operator == "!=":
	    return value != leftvalue
	elif operator == "~":
	    return leftvalue.find(value) >= 0

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
	    if self.res.history.urlparse.file_extension == value:
		cond = True
	elif adv_element == 'site':
	    if self.res.history.urlparse.netloc.rfind(value) >= 0:
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
	    value = FuzzResult.ERROR_CODE

	if value == 'BBB':
	    if element == 'l' or element == 'lines':
		value = self.baseline.lines
	    elif element == 'c' or element == 'code':
		value = self.baseline.code
	    elif element == 'w' or element == 'words':
		value = self.baseline.words
	    elif element == 'h' or element == 'chars':
		value = self.baseline.chars
	    elif element == 'index' or element == 'i':
		value = self.baseline.nres

	test = dict(w=self.res.words, c=self.res.code, l=self.res.lines, h=self.res.chars, i=self.res.nres, \
                words=self.res.words, code=self.res.code, lines=self.res.lines, chars=self.res.chars, index=self.res.nres)
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
	filter_string = self.hideparams['filter_string']
	if filter_string and PYPARSING:
	    self.res = res
	    try:
		return self.finalformula.parseString(filter_string)[0]
	    except ParseException, e:
		raise FuzzException(FuzzException.FATAL, "Incorrect filter expression. It should be composed of: c,l,w,h,index,intext,inurl,site,inheader,filetype,ispath,hasquery;not,and,or;=,<,>,!=,<=,>=")
            except AttributeError, e:
		raise FuzzException(FuzzException.FATAL, "It is only possible to use advanced filters when using a non-string payload. %s" % str(e))
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

	if "XXX" in ffilter.hideparams['codes']:
	    ffilter.hideparams['codes'].append(str(FuzzResult.ERROR_CODE))

        return ffilter
