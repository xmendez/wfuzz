from .exception import FuzzExceptIncorrectFilter, FuzzExceptBadOptions, FuzzExceptInternalError
from .fuzzobjects import FuzzResult

import re
import collections
import urllib

from .facade import Facade


PYPARSING = True
try:
    from  pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal, alphas, alphanums, Or, OneOrMore, QuotedString, printables
    from  pyparsing import ParseException
except ImportError:
    PYPARSING = False


class FuzzResFilter:
    def __init__(self, ffilter = None, filter_string = None):
	if PYPARSING:
            quoted_str_value = QuotedString('\'', unquoteResults=True, escChar='\\')
            int_values = Word("0123456789")
            error_value = Literal("XXX").setParseAction(self.__compute_xxx_value)
            bbb_value = Literal("BBB").setParseAction(self.__compute_bbb_value)
            field_value = Word(alphas + "." + "_" + "-")

            basic_primitives = int_values | quoted_str_value

            operator_names = oneOf("m d e un u r l sw unique startswith decode encode unquote replace lower upper").setParseAction(lambda s,l,t: [ (l,t[0])])

            fuzz_symbol = (Suppress("FUZ") + Optional(Word("23456789"), 1).setParseAction( lambda s,l,t: [ int(t[0])-1 ] ) +  Suppress("Z")).setParseAction(self.__compute_fuzz_symbol)
            operator_call = Group(Suppress("|") + operator_names + Suppress("(") + Optional(basic_primitives, None) + Optional(Suppress(",") + basic_primitives, None) + Suppress(")"))

            fuzz_value = (fuzz_symbol + Optional(Suppress("[") + field_value + Suppress("]"), None)).setParseAction(self.__compute_fuzz_value)
            fuzz_value_op = ((fuzz_symbol + Suppress("[") + Optional(field_value)).setParseAction(self.__compute_fuzz_value) + operator_call + Suppress("]")).setParseAction(self.__compute_perl_value)
            fuzz_value_op2 = ((fuzz_symbol + operator_call).setParseAction(self.__compute_perl_value))

            res_value_op = (Word(alphas + "." + "_" + "-").setParseAction(self.__compute_res_value) + Optional(operator_call, None)).setParseAction(self.__compute_perl_value)
            basic_primitives_op = (basic_primitives + Optional(operator_call, None)).setParseAction(self.__compute_perl_value)

            fuzz_statement = fuzz_value ^ fuzz_value_op ^ fuzz_value_op2 ^ res_value_op ^ basic_primitives_op

            operator = oneOf("and or")
            not_operator = Optional(oneOf("not"), "notpresent")

            symbol_expr = Group(fuzz_statement + oneOf("= != < > >= <= =~ !~ ~") + (bbb_value ^ error_value ^ fuzz_statement ^ basic_primitives)).setParseAction(self.__compute_expr)

            definition = fuzz_statement ^ symbol_expr
            definition_not = not_operator + definition
            definition_expr = definition_not + ZeroOrMore( operator + definition_not)

            nested_definition = Group(Suppress("(") + definition_expr + Suppress(")"))
            nested_definition_not = not_operator + nested_definition

            self.finalformula = (nested_definition_not ^ definition_expr) + ZeroOrMore( operator + (nested_definition_not ^ definition_expr))

	    definition_not.setParseAction(self.__compute_not_operator)
	    nested_definition_not.setParseAction(self.__compute_not_operator)
	    nested_definition.setParseAction(self.__compute_formula)
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
        self.stack = {}

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

    def __compute_res_value(self, tokens):
        self.stack["field"] = tokens[0]

        return self.res.get_field(self.stack["field"])

    def __compute_fuzz_symbol(self, tokens):
	i = tokens[0]

        try:
            return self.res.payload[i]
        except IndexError:
            raise FuzzExceptIncorrectFilter("Non existent FUZZ payload! Use a correct index.")
        except AttributeError:
            if i == 0:
                return self.res
            else:
                raise FuzzExceptIncorrectFilter("Non existent FUZZ payload! Use a correct index.")

    def __compute_fuzz_value(self, tokens):
	fuzz_val, field = tokens

        self.stack["field"] = field

        try:
            return fuzz_val.get_field(field) if field else fuzz_val
        except IndexError:
            raise FuzzExceptIncorrectFilter("Non existent FUZZ payload! Use a correct index.")
        except AttributeError, e:
            raise FuzzExceptIncorrectFilter("A field expression must be used with a fuzzresult payload not a string. %s" % str(e))

    def __compute_bbb_value(self, tokens):
        element = self.stack["field"]

	if self.baseline == None:
	    raise FuzzExceptBadOptions("FilterQ: specify a baseline value when using BBB")

        if element == 'l' or element == 'lines':
            ret = self.baseline.lines
        elif element == 'c' or element == 'code':
            ret = self.baseline.code
        elif element == 'w' or element == 'words':
            ret = self.baseline.words
        elif element == 'h' or element == 'chars':
            return self.baseline.chars
        elif element == 'index' or element == 'i':
            ret = self.baseline.nres

        return str(ret)

    def __compute_perl_value(self, tokens):
        leftvalue, exp = tokens 
        
        if exp:
            loc_op, middlevalue, rightvalue = exp
            loc, op = loc_op
        else:
            return leftvalue


        if (op == "un" or op == "unquote") and middlevalue == None and rightvalue == None:
            ret = urllib.unquote(leftvalue)
        elif (op == "e" or op == "encode") and middlevalue != None and rightvalue == None:
            ret = Facade().encoders.get_plugin(middlevalue)().encode(leftvalue)
        elif (op == "d" or op == "decode") and middlevalue != None and rightvalue == None:
            ret = Facade().encoders.get_plugin(middlevalue)().decode(leftvalue)
        elif op == "r" or op == "replace":
            return leftvalue.replace(middlevalue, rightvalue)
        elif op == "upper":
            return leftvalue.upper()
        elif op == "lower" or op == "l":
            return leftvalue.lower()
	elif op == 'startswith' or op == "sw":
            return leftvalue.strip().startswith(middlevalue)
	elif op == 'unique' or op == "u":
            if leftvalue not in self._cache[loc]:
                self._cache[loc].add(leftvalue)
                return True
            else:
                return False
        else:
            raise FuzzExceptBadOptions("Bad format, expression should be m,d,e,r,s(value,value)")

        return ret

    def __compute_xxx_value(self, tokens):
        return FuzzResult.ERROR_CODE
        
    def __compute_expr(self, tokens):
	leftvalue, operator, rightvalue = tokens[0]

        try:
            if operator == "=":
                return leftvalue == rightvalue
            elif operator == "<=":
                return leftvalue <= rightvalue
            elif operator == ">=":
                return leftvalue >= rightvalue
            elif operator == "<":
                return leftvalue < rightvalue
            elif operator == ">":
                return leftvalue > rightvalue
            elif operator == "!=":
                return leftvalue != rightvalue
            elif operator == "=~":
                regex = re.compile(rightvalue, re.MULTILINE|re.DOTALL)
                return regex.search(leftvalue) is not None
            elif operator == "!~":
                return rightvalue.lower() not in leftvalue.lower()
            elif operator == "~":
                return rightvalue.lower() in leftvalue.lower()
        except TypeError,e:
	    raise FuzzExceptBadOptions("Invalid regex expression used in filter: %s" % str(e))
        except ParseException, e:
	    raise FuzzExceptBadOptions("Invalid regex expression used in filter: %s" % str(e))

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
		return self.finalformula.parseString(filter_string, parseAll = True)[0]
	    except ParseException, e:
		raise FuzzExceptIncorrectFilter("Incorrect filter expression, check documentation.")
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
