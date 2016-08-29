# mimicking nmap script filter


#nmap --script "http-*"
#    Loads all scripts whose name starts with http-, such as http-auth and http-open-proxy. The argument to --script had to be in quotes to protect the wildcard from the shell.
# not valid for categories!
#
#More complicated script selection can be done using the and, or, and not operators to build Boolean expressions. The operators have the same precedence[12] as in Lua: not is the
#highest, followed by and and then or. You can alter precedence by using parentheses. Because expressions contain space characters it is necessary to quote them.
#
#nmap --script "not intrusive"
#    Loads every script except for those in the intrusive category.
#
#nmap --script "default or safe"
#    This is functionally equivalent to nmap --script "default,safe". It loads all scripts that are in the default category or the safe category or both.
#
#nmap --script "default and safe"
#    Loads those scripts that are in both the default and safe categories.
#
#nmap --script "(default or safe or intrusive) and not http-*"
#    Loads scripts in the default, safe, or intrusive categories, except for those whose names start with http-.


from types import ListType
PYPARSING = True
try:
    from pyparsing import Word, Group, oneOf, Optional, Suppress, ZeroOrMore, Literal, alphas, alphanums
except ImportError:
    PYPARSING = False
    
class IFilter:
    def is_visible(self, plugin, filter_string):
	raise NotImplemented

class Filter(IFilter):
    def __init__(self):
	if PYPARSING:
	    category = Word( alphas + "_-*", alphanums + "_-*" )
	    operator = oneOf("and or ,")
	    neg_operator = "not"
	    elementRef = category
	    definition = elementRef + ZeroOrMore( operator + elementRef)
	    nestedformula = Group(Suppress(Optional(Literal("("))) + definition + Suppress(Optional(Literal(")"))))
	    neg_nestedformula = Optional(neg_operator) + nestedformula
	    self.finalformula = neg_nestedformula + ZeroOrMore( operator + neg_nestedformula)

	    elementRef.setParseAction(self.__compute_element)
	    neg_nestedformula.setParseAction(self.__compute_neg_formula)
	    nestedformula.setParseAction(self.__compute_formula)
	    self.finalformula.setParseAction(self.__myreduce)

    def __compute_neg_formula(self, tokens):
	if len(tokens) > 1 and tokens[0] == 'not':
	    return not tokens[1]
	else:
	    return tokens[0]

    def __compute_element(self, tokens):
	item = tokens[0]
	wildc_index = item.find("*")

	if wildc_index > 0:
	    return self.plugin.name.startswith(item[:wildc_index])
	else:
	    if type(self.plugin.category) == ListType:
		return (item in self.plugin.category or self.plugin.name == item)
	    else:
		return (self.plugin.category == item  or self.plugin.name == item)

    def __myreduce(self, elements):
	first = elements[0]
	for i in range(1, len(elements), 2):
	    if elements[i] == "and":
		first = (first and elements[i+1])
	    elif elements[i] == "or" or elements[i] == ",":
		first = (first or elements[i+1])

	return first

    def __compute_formula(self, tokens):
	return self.__myreduce(tokens[0])

    def simple_filter(self, plugin, filter_string):
	ret = False

	for item in filter_string.split(","):
	    wildc_index = item.find("*")
	    if wildc_index > 0:
		ret = (item in plugin.category or plugin.name.startswith(item[:wildc_index]))
	    else:
		ret = (item in plugin.category or plugin.name == item)

	return ret

    def simple_filter_banned_keywords(self, filter_string):
	    if filter_string.find("(") >=0:
		return True
	    elif filter_string.find(")") >=0:
		return True
	    elif any(x in ["or", "not", "and"] for x in filter_string.split(" ")):
		return True
	    else: 
		return False

    def is_visible(self, plugin, filter_string):
	self.plugin = plugin
	if PYPARSING:
	    return self.finalformula.parseString(filter_string)[0]
	else:
	    if self.simple_filter_banned_keywords(filter_string):
		raise Exception("Pyparsing missing, complex filters not allowed.")
	    else:
		return self.simple_filter(plugin, filter_string)

if __name__ == "__main__":
    tests = []
    tests.append("not intrusive")
    tests.append("intrusive")
    tests.append("safe")
    tests.append("not safe")
    tests.append("not http-adas")
    tests.append("default or safe")
    tests.append("default,safe")
    tests.append("default and safe")
    tests.append("not default or not safe")
    tests.append("(default or safe or intrusive) and not http")
    tests.append("not (default or safe or intrusive) and not http")
    tests.append("not (default or safe or intrusive) and safe")
    tests.append("not (default or safe or intrusive) or safe")
    tests.append("not (default or intrusive) and safe")
    tests.append("http-*")
    tests.append("http-test")
    tests.append("not http-test")
    tests.append("not safe")

    class t:
	category = ["safe"]
	name = "http-test"

    res = t()

    print "cat = %s, name = %s\n\n" % (res.category, res.name)
    for i in tests:
	f = Filter()
	print "%s := %s" % (str(i), f.is_visible(res, i))

