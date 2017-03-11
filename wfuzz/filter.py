from .exception import FuzzExceptIncorrectFilter, FuzzExceptBadOptions, FuzzExceptInternalError
from .fuzzobjects import FuzzResult

import re
import collections
import urllib


PYPARSING = True
try:
    from  pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal, alphanums, Or, OneOrMore, QuotedString, printables
    from  pyparsing import ParseException
except ImportError:
    PYPARSING = False


class FuzzResFilter:
    def __init__(self, ffilter = None, filter_string = None):
	if PYPARSING:
	    basic_symbol = oneOf("c code l lines w words h chars i index")
	    adv_symbol = oneOf("intext inurl site inheader inrheader filetype")
	    adv_symbol_bool = oneOf("hasquery ispath")
            fuzz_symbol = Suppress("FUZZ[") + Word( alphanums + "." ) + Suppress(Literal("]"))

            field_element = Suppress(Literal("FUZ")) + Optional(Word("0123456789"), 0) +  Suppress(Literal("Z")) + Optional(Suppress(Literal("[")) + Word( alphanums + "." ) + Suppress(Literal("]")), "")
            quoted_str_element = QuotedString('\'', unquoteResults=True, escChar='\\')
            quoted_str_element_opt = Word(alphanums)| quoted_str_element

	    basic_symbol_values = Word("0123456789") | oneOf("XXX BBB")
            adv_symbol_values = field_element | quoted_str_element_opt
            unquote_operator = Optional("unquote(", "notpresent") + adv_symbol_values + Optional(Suppress(Literal(")")))

            unique_operator = Suppress("unique(") + fuzz_symbol + Suppress(Literal(")"))
            sed_operator = Suppress("replace(") + fuzz_symbol + Suppress(Literal(",")) + quoted_str_element + Suppress(Literal(",")) + quoted_str_element + Suppress(Literal(")"))
	    operator = oneOf("and or")
	    not_operator = Optional(oneOf("not"), "notpresent")

	    basic_symbol_expr = Group(basic_symbol + oneOf("= != < > >= <=") + basic_symbol_values)
	    adv_symbol_expr = Group(adv_symbol + oneOf("= != =~ !~ ~") + unquote_operator)
	    fuzz_symbol_expr = Group(fuzz_symbol + oneOf("= != =~ !~ ~") + quoted_str_element_opt)

            definition = sed_operator | fuzz_symbol_expr | adv_symbol_expr | basic_symbol_expr | adv_symbol_bool | unique_operator
            definition_not = not_operator + definition
	    definition_expr = definition_not + ZeroOrMore( operator + definition_not)

	    nested_definition = Group(Suppress(Optional(Literal("("))) + definition_expr + Suppress(Optional(Literal(")"))))
	    nested_definition_not = not_operator + nested_definition

	    self.finalformula = nested_definition_not + ZeroOrMore( operator + nested_definition_not)

	    unquote_operator.setParseAction(self.__compute_unquote_operator)
	    definition_not.setParseAction(self.__compute_not_operator)
	    nested_definition_not.setParseAction(self.__compute_not_operator)
	    field_element.setParseAction(self.__compute_field_element)
	    basic_symbol_expr.setParseAction(self.__compute_element)
	    adv_symbol_expr.setParseAction(self.__compute_adv_element)
	    adv_symbol_bool.setParseAction(self.__compute_adv_element_bool)
	    fuzz_symbol_expr.setParseAction(self.__compute_filter_element)
	    sed_operator.setParseAction(self.__compute_sed_element)
	    nested_definition.setParseAction(self.__compute_formula)
	    unique_operator.setParseAction(self.__compute_special_element)
	    self.finalformula.setParseAction(self.__myreduce)

        if ffilter is not None and filter_string is not None:
            raise FuzzExceptInternalError(FuzzException.FATAL, "A filter must be initilized with a filter string or an object, not both")

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

	self.baseline = None

        self._cache = collections.defaultdict(set)

    def set_baseline(self, res):
	if FuzzResult.BASELINE_CODE in self.hideparams['lines']:
	    self.hideparams['lines'].append(res.lines)
	if FuzzResult.BASELINE_CODE in self.hideparams['codes']:
	    self.hideparams['codes'].append(res.code)
	if FuzzResult.BASELINE_CODE in self.hideparams['words']:
	    self.hideparams['words'].append(res.words)
	if FuzzResult.BASELINE_CODE in self.hideparams['chars']:
	    self.hideparams['chars'].append(res.chars)

	self.baseline = res

    def __convertIntegers(self, tokens):
	return int(tokens[0])

    def __compute_unquote_operator(self, tokens):
        operator, value = tokens
        if operator == "unquote(":
            return urllib.unquote(value)
        return value

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
	adv_element = tokens[0]

	cond = False

	if adv_element == 'hasquery':
	    if self.res.history.urlparse.query:
		cond = True

	elif adv_element == 'ispath':
	    if self.res.history.is_path:
		cond = True

        return cond

    def __compute_field_element(self, tokens):
	i, field = tokens

        try:
            return self.res.payload[int(i)].get_field(field) if field else self.res.payload[int(i)]
        except IndexError:
            raise FuzzExceptIncorrectFilter("Non existent FUZZ payload! Use a correct index.")
        except AttributeError:
            raise FuzzExceptIncorrectFilter("A field expression must be used with a fuzzresult payload not a string.")

    def __compute_filter_element(self, tokens):
	filter_element, operator, value = tokens[0]

        leftvalue = self.res.get_field(filter_element)
	cond = False

	if operator == "=":
	    return value == leftvalue
	elif operator == "!=":
	    return value != leftvalue
	elif operator == "~":
	    return value in leftvalue
	elif operator == "=~":
            regex = re.compile(value, re.MULTILINE|re.DOTALL)
            return regex.search(leftvalue) is not None
	elif operator == "!~":
            regex = re.compile(value, re.MULTILINE|re.DOTALL)
            return regex.search(leftvalue) is None

    def __compute_adv_element(self, tokens):
	adv_element, operator, value = tokens[0]

	cond = False

        try:
            if adv_element == 'intext':
                test = self.res.history.content
            elif adv_element == 'inurl':
                test = self.res.url
            elif adv_element == 'filetype':
                test = self.res.history.urlparse.file_extension
            elif adv_element == 'site':
                test = self.res.history.urlparse.netloc
            elif adv_element == 'inheader':
                test = "\n".join([': '.join(k) for k in self.res.history.headers.response.items()])
            elif adv_element == 'inrheader':
                test = "\n".join([': '.join(k) for k in self.res.history.headers.request.items()])

            if operator == "=":
                return test == value
            elif operator == "!=":
                return test != value
            elif operator == "=~":
                regex = re.compile(value, re.MULTILINE|re.DOTALL)
                return regex.search(test) is not None
            elif operator == "!~":
                regex = re.compile(value, re.MULTILINE|re.DOTALL)
                return regex.search(test) is None
            elif operator == "~":
                return value in test
        except TypeError:
            raise FuzzExceptIncorrectFilter("Using a complete fuzzresult as a filter, specify field or use string.")

	return cond if operator == "=" else not cond

    def __compute_element(self, tokens):
	element, operator, value = tokens[0]
	
	if value == 'BBB' and self.baseline == None:
	    raise FuzzExceptBadOptions("FilterQ: specify a baseline value when using BBB")

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

    def __compute_not_operator(self, tokens):
        operator, value = tokens

        if operator == "not":
            return not value

	return value

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
		raise FuzzExceptIncorrectFilter("Incorrect filter expression. It should be composed of: c,l,w,h,index,intext,inurl,site,inheader,filetype,ispath,hasquery;not,and,or;=,<,>,!=,<=,>=")
            except AttributeError, e:
		raise FuzzExceptIncorrectFilter("It is only possible to use advanced filters when using a non-string payload. %s" % str(e))
	else:
	    if self.hideparams['codes_show'] is None:
		cond1 = True
	    else:
		cond1 = not self.hideparams['codes_show']

	    if self.hideparams['regex_show'] is None:
		cond2 = True
	    else:
		cond2 = not self.hideparams['regex_show']

	    if res.code in self.hideparams['codes'] \
		or res.lines in self.hideparams['lines'] \
		or res.words in self.hideparams['words'] \
		or res.chars in self.hideparams['chars']:
		    cond1 = self.hideparams['codes_show']

	    if self.hideparams['regex']:
		if self.hideparams['regex'].search(res.history.content):
		    cond2 = self.hideparams['regex_show']

	    return (cond1 and cond2)

    @staticmethod
    def from_options(filter_options):
        ffilter = FuzzResFilter()

	ffilter.hideparams["filter_string"] = filter_options["filter"]

	try:
	    if filter_options["ss"] is not None:
		ffilter.hideparams['regex_show'] = True
		ffilter.hideparams['regex'] = re.compile(filter_options['ss'], re.MULTILINE|re.DOTALL)

	    elif filter_options["hs"] is not None:
		ffilter.hideparams['regex_show'] = False
		ffilter.hideparams['regex'] = re.compile(filter_options['hs'], re.MULTILINE|re.DOTALL)
	except Exception, e:
	    raise FuzzExceptBadOptions("Invalid regex expression used in filter: %s" % str(e))

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
