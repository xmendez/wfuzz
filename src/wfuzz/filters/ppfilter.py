from ..exception import FuzzExceptIncorrectFilter, FuzzExceptBadOptions
from ..helpers.obj_dyn import (
    rgetattr,
    rsetattr,
)
from ..helpers.str_func import value_in_any_list_item
from ..helpers.obj_dic import DotDict
from ..helpers.utils import diff

import re
import collections
import operator

# Python 2 and 3: alternative 4
try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

from ..facade import Facade, ERROR_CODE


PYPARSING = True
try:
    from pyparsing import (
        Word,
        Group,
        oneOf,
        Optional,
        Suppress,
        ZeroOrMore,
        Literal,
        QuotedString,
        ParseException,
        Regex,
    )
except ImportError:
    PYPARSING = False


class FuzzResFilter:
    FUZZ_MARKER_REGEX = re.compile(r"FUZ\d*Z", re.MULTILINE | re.DOTALL)

    def __init__(self, filter_string=None):
        self.filter_string = filter_string
        self.baseline = None

        quoted_str_value = QuotedString("'", unquoteResults=True, escChar="\\")
        int_values = Word("0123456789").setParseAction(lambda s, l, t: [int(t[0])])
        error_value = Literal("XXX").setParseAction(self.__compute_xxx_value)

        operator_call = Regex(
            r"\|(?P<operator>(m|d|e|un|u|r|l|sw|gre|gregex|unique|startswith|decode|encode|unquote|replace|lower|upper))"
            r"\((?:(?P<param1>('.*?'|\d+))(?:,(?P<param2>('.*?'|\d+)))?)?\)",
            asMatch=True,
        ).setParseAction(lambda s, l, t: [(l, t[0])])

        fuzz_symbol = Regex(
            r"FUZ(?P<index>\d)*Z(?:\[(?P<field>(\w|_|-|\.)+)\])?", asMatch=True
        ).setParseAction(self._compute_fuzz_symbol)
        res_symbol = Regex(
            r"(description|nres|code|chars|lines|words|md5|content|timer|url|l|w|c|(r|history|plugins)(\w|_|-|\.)*|h)"
        ).setParseAction(self._compute_res_symbol)
        bbb_symbol = Regex(
            r"BBB(?:\[(?P<field>(\w|_|-|\.)+)\])?", asMatch=True
        ).setParseAction(self.__compute_bbb_symbol)

        diff_call = Group(
            Suppress(Literal("|"))
            + Literal("diff")
            + Suppress(Literal("("))
            + (fuzz_symbol | res_symbol | bbb_symbol | int_values | quoted_str_value)
            + Suppress(")")
        )

        fuzz_statement = Group(
            (fuzz_symbol | res_symbol | bbb_symbol | int_values | quoted_str_value)
            + Optional(diff_call | operator_call, None)
        ).setParseAction(self.__compute_res_value)

        operator = oneOf("and or")
        not_operator = Optional(oneOf("not"), "notpresent")

        symbol_expr = Group(
            fuzz_statement
            + oneOf("= == != < > >= <= =~ !~ ~ := =+ =-")
            + (error_value | fuzz_statement)
        ).setParseAction(self.__compute_expr)

        definition = symbol_expr ^ fuzz_statement
        definition_not = not_operator + definition
        definition_expr = definition_not + ZeroOrMore(operator + definition_not)

        nested_definition = Group(Suppress("(") + definition_expr + Suppress(")"))
        nested_definition_not = not_operator + nested_definition

        self.finalformula = (nested_definition_not | definition_expr) + ZeroOrMore(
            operator + (nested_definition_not | definition_expr)
        )

        definition_not.setParseAction(self.__compute_not_operator)
        nested_definition_not.setParseAction(self.__compute_not_operator)
        nested_definition.setParseAction(self.__compute_formula)
        self.finalformula.setParseAction(self.__myreduce)

        self.res = None
        self.stack = []
        self._cache = collections.defaultdict(set)

    def set_baseline(self, res):
        self.baseline = res

    def _compute_res_symbol(self, tokens):
        return self._get_field_value(self.res, tokens[0])

    def _compute_fuzz_symbol(self, tokens):
        match_dict = tokens[0].groupdict()
        p_index = int(match_dict["index"]) if match_dict["index"] is not None else 1
        fuzz_val = None

        try:
            fuzz_val = self.res.payload_man.get_payload_content(p_index)
        except IndexError:
            raise FuzzExceptIncorrectFilter(
                "Non existent FUZZ payload! Use a correct index."
            )

        if match_dict["field"]:
            fuzz_val = self._get_field_value(fuzz_val, match_dict["field"])

        return fuzz_val

    def __compute_res_value(self, tokens):
        fuzz_val, token_tuple = tokens[0]

        if token_tuple:
            location, operator_match = token_tuple

            if location == "diff":
                return diff(operator_match, fuzz_val)
            else:
                if operator_match and operator_match.groupdict()["operator"]:
                    fuzz_val = self._get_operator_value(
                        location, fuzz_val, operator_match.groupdict()
                    )

        if isinstance(fuzz_val, list):
            return [fuzz_val]
        return fuzz_val

    def _get_payload_value(self, p_index):
        try:
            return self.res.payload_man.get_payload_content(p_index)
        except IndexError:
            raise FuzzExceptIncorrectFilter(
                "Non existent FUZZ payload! Use a correct index."
            )

    def _get_field_value(self, fuzz_val, field):
        self.stack.append(field)

        try:
            ret = rgetattr(fuzz_val, field)
        except IndexError:
            raise FuzzExceptIncorrectFilter(
                "Non existent FUZZ payload! Use a correct index."
            )
        except AttributeError as e:
            raise FuzzExceptIncorrectFilter(
                "Attribute {} not found in fuzzresult or using a string payload. {}".format(
                    field, str(e)
                )
            )

        if isinstance(ret, list):
            return [ret]
        return ret

    def __compute_bbb_symbol(self, tokens):
        if self.baseline is None:
            raise FuzzExceptBadOptions(
                "FilterQ: specify a baseline value when using BBB"
            )

        match_dict = tokens[0].groupdict()

        ret = None

        if match_dict["field"]:
            ret = self._get_field_value(self.baseline, match_dict["field"])
        else:
            element = self.stack.pop() if self.stack else None

            if element == "l" or element == "lines":
                ret = self.baseline.lines
            elif element == "c" or element == "code":
                ret = self.baseline.code
            elif element == "w" or element == "words":
                ret = self.baseline.words
            elif element == "h" or element == "chars":
                return self.baseline.chars
            elif element == "index" or element == "i":
                ret = self.baseline.nres
            else:
                ret = self.baseline.payload_man.get_payload_content(1)

        return ret

    def _get_operator_value(self, location, fuzz_val, match_dict):
        op = match_dict["operator"]
        param1 = match_dict["param1"]
        param2 = match_dict["param2"]

        if param1:
            param1 = param1.strip("'")
        if param2:
            param2 = param2.strip("'")

        if (op == "un" or op == "unquote") and param1 is None and param2 is None:
            ret = unquote(fuzz_val)
        elif (op == "e" or op == "encode") and param1 is not None and param2 is None:
            ret = Facade().encoders.get_plugin(param1)().encode(fuzz_val)
        elif (op == "d" or op == "decode") and param1 is not None and param2 is None:
            ret = Facade().encoders.get_plugin(param1)().decode(fuzz_val)
        elif op == "r" or op == "replace":
            return fuzz_val.replace(param1, param2)
        elif op == "upper":
            return fuzz_val.upper()
        elif op == "lower" or op == "l":
            return fuzz_val.lower()
        elif op == "gregex" or op == "gre":
            search_res = None
            try:
                regex = re.compile(param1)
                search_res = regex.search(fuzz_val)
            except re.error as e:
                raise FuzzExceptBadOptions(
                    "Invalid regex expression used in expression: %s" % str(e)
                )

            if search_res is None:
                return ""
            return search_res.group(1)
        elif op == "startswith" or op == "sw":
            return fuzz_val.strip().startswith(param1)
        elif op == "unique" or op == "u":
            if fuzz_val not in self._cache[location]:
                self._cache[location].add(fuzz_val)
                return True
            else:
                return False
        else:
            raise FuzzExceptBadOptions(
                "Bad format, expression should be m,d,e,r,s(value,value)"
            )

        return ret

    def __compute_xxx_value(self, tokens):
        return ERROR_CODE

    def __compute_expr(self, tokens):
        leftvalue, exp_operator, rightvalue = tokens[0]

        # a bit hacky but we don't care about fields in the right hand side of the expression
        if len(self.stack) > 1:
            self.stack.pop()

        field_to_set = self.stack.pop() if self.stack else None

        try:
            if exp_operator in ["=", "=="]:
                return str(leftvalue) == str(rightvalue)
            elif exp_operator == "<=":
                return int(leftvalue) <= int(rightvalue)
            elif exp_operator == ">=":
                return int(leftvalue) >= int(rightvalue)
            elif exp_operator == "<":
                return int(leftvalue) < int(rightvalue)
            elif exp_operator == ">":
                return int(leftvalue) > int(rightvalue)
            elif exp_operator == "!=":
                return leftvalue != rightvalue
            elif exp_operator == "=~":
                regex = re.compile(rightvalue, re.MULTILINE | re.DOTALL)
                return regex.search(leftvalue) is not None
            elif exp_operator in ["!~", "~"]:
                ret = True

                if isinstance(leftvalue, str):
                    ret = rightvalue.lower() in leftvalue.lower()
                elif isinstance(leftvalue, list):
                    ret = value_in_any_list_item(rightvalue, leftvalue)
                elif isinstance(leftvalue, dict) or isinstance(leftvalue, DotDict):
                    ret = rightvalue.lower() in str(leftvalue).lower()
                else:
                    raise FuzzExceptBadOptions(
                        "Invalid operand type {}".format(rightvalue)
                    )

                return ret if exp_operator == "~" else not ret
            elif exp_operator == ":=":
                rsetattr(self.res, field_to_set, rightvalue, None)
            elif exp_operator == "=+":
                rsetattr(self.res, field_to_set, rightvalue, operator.add)
            elif exp_operator == "=-":
                if isinstance(rightvalue, str):
                    rsetattr(self.res, field_to_set, rightvalue, lambda x, y: y + x)
                else:
                    rsetattr(self.res, field_to_set, rightvalue, operator.sub)
        except re.error as e:
            raise FuzzExceptBadOptions(
                "Invalid regex expression used in expression: %s" % str(e)
            )
        except TypeError as e:
            raise FuzzExceptBadOptions(
                "Invalid operand types used in expression: %s" % str(e)
            )
        except ParseException as e:
            raise FuzzExceptBadOptions("Invalid filter: %s" % str(e))

        return True

    def __myreduce(self, elements):
        first = elements[0]
        for i in range(1, len(elements), 2):
            if elements[i] == "and":
                first = first and elements[i + 1]
            elif elements[i] == "or":
                first = first or elements[i + 1]

        self.stack = []

        if isinstance(first, list):
            return [first]
        return first

    def __compute_not_operator(self, tokens):
        operator, value = tokens

        if operator == "not":
            return not value

        if isinstance(value, list):
            return [value]
        return value

    def __compute_formula(self, tokens):
        return self.__myreduce(tokens[0])

    def is_active(self):
        return self.filter_string

    def is_visible(self, res, filter_string=None):
        if filter_string is None:
            filter_string = self.filter_string
        self.res = res
        try:
            return self.finalformula.parseString(filter_string, parseAll=True)[0]
        except ParseException as e:
            raise FuzzExceptIncorrectFilter(
                "Incorrect filter expression, check documentation. {}".format(str(e))
            )
        except AttributeError as e:
            raise FuzzExceptIncorrectFilter(
                "It is only possible to use advanced filters when using a non-string payload. %s"
                % str(e)
            )

    def get_fuzz_words(self):
        fuzz_words = self.FUZZ_MARKER_REGEX.findall(self.filter_string)

        return fuzz_words


class FuzzResFilterSlice(FuzzResFilter):
    # When using slice we don't have previous payload context but directly a word from the dictionary
    def _compute_fuzz_symbol(self, tokens):
        match_dict = tokens[0].groupdict()

        p_index = match_dict["index"] if match_dict["index"] is not None else 1

        if p_index != 1:
            raise FuzzExceptIncorrectFilter(
                "Non existent FUZZ payload! Use a correct index."
            )

        fuzz_val = self.res

        if match_dict["field"]:
            fuzz_val = self._get_field_value(self.res, match_dict["field"])

        return fuzz_val
