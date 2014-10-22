from framework.core.myexception import FuzzException
from threading import Thread

from framework.fuzzer.fuzzobjects import FuzzResult
from framework.utils.myqueue import FuzzQueue

PYPARSING = True
try:
    from  pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal
    from  pyparsing import ParseException
except ImportError:
    PYPARSING = False
    
class FilterQ(FuzzQueue):
    def __init__(self, ffilter, queue_out):
	FuzzQueue.__init__(self, queue_out)
	Thread.__init__(self)
	self.setName('filter_thread')

	self.queue_out = queue_out

	if PYPARSING:
	    element = oneOf("c l w h")
	    digits = "XB0123456789"
	    integer = Word( digits )#.setParseAction( self.__convertIntegers )
	    elementRef = Group(element + oneOf("= != < > >= <=") + integer)
	    operator = oneOf("and or")
	    definition = elementRef + ZeroOrMore( operator + elementRef)
	    nestedformula = Group(Suppress(Optional(Literal("("))) + definition + Suppress(Optional(Literal(")"))))
	    self.finalformula = nestedformula + ZeroOrMore( operator + nestedformula)

	    elementRef.setParseAction(self.__compute_element)
	    nestedformula.setParseAction(self.__compute_formula)
	    self.finalformula.setParseAction(self.__myreduce)

	self.res = None
	self.hideparams = ffilter

	if "XXX" in self.hideparams['codes']:
	    self.hideparams['codes'].append("0")

	self.baseline = None

    def get_name(self):
	return 'filter_thread'

    def _cleanup(self):
	pass

    def process(self, prio, item):
	if item.is_baseline:
	    self.baseline = self._set_baseline_fuzz(item)
	item.is_visible = self.is_visible(item)
	self.send(item)

    def _set_baseline_fuzz(self, res):
	if "BBB" in self.hideparams['lines']:
	    self.hideparams['lines'].append(str(res.lines))
	if "BBB" in self.hideparams['codes']:
	    self.hideparams['codes'].append(str(res.code))
	if "BBB" in self.hideparams['words']:
	    self.hideparams['words'].append(str(res.words))
	if "BBB" in self.hideparams['chars']:
	    self.hideparams['chars'].append(str(res.chars))

	return res

    def __convertIntegers(self, tokens):
	return int(tokens[0])

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

	test = dict(w=self.res.words, c=self.res.code, l=self.res.lines, h=self.res.chars)
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
		raise FuzzException(FuzzException.FATAL, "Incorrect filter expression. It should be composed of: c,l,w,h/and,or/=,<,>,!=,<=,>=")
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
		if self.hideparams['regex'].search(res.history.fr_content()):
		    cond2 = self.hideparams['regex_show']

	    return (cond1 and cond2)

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
