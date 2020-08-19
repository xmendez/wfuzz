import re
import sys
import six


from .obj_dic import DotDict


def json_minify(string, strip_space=True):
    """
    Created on 20/01/2011
    v0.2 (C) Gerald Storer
    MIT License
    Based on JSON.minify.js:
    https://github.com/getify/JSON.minify
    Contributers:
    - Pradyun S. Gedam (conditions and variable names changed)
    """

    tokenizer = re.compile(r'"|(/\*)|(\*/)|(//)|\n|\r')
    end_slashes_re = re.compile(r"(\\)*$")

    in_string = False
    in_multi = False
    in_single = False

    new_str = []
    index = 0

    for match in re.finditer(tokenizer, string):

        if not (in_multi or in_single):
            tmp = string[index : match.start()]
            if not in_string and strip_space:
                # replace white space as defined in standard
                tmp = re.sub("[ \t\n\r]+", "", tmp)
            new_str.append(tmp)

        index = match.end()
        val = match.group()

        if val == '"' and not (in_multi or in_single):
            escaped = end_slashes_re.search(string, 0, match.start())

            # start of string or unescaped quote character to end string
            if not in_string or (escaped is None or len(escaped.group()) % 2 == 0):
                in_string = not in_string
            # include " character in next catch
            index -= 1
        elif not (in_string or in_multi or in_single):
            if val == "/*":
                in_multi = True
            elif val == "//":
                in_single = True
        elif val == "*/" and in_multi and not (in_string or in_single):
            in_multi = False
        elif val in "\r\n" and not (in_multi or in_string) and in_single:
            in_single = False
        elif not ((in_multi or in_single) or (val in " \r\n\t" and strip_space)):
            new_str.append(val)

    new_str.append(string[index:])
    return "".join(new_str)


def python2_3_convert_from_unicode(text):
    if sys.version_info >= (3, 0):
        return text
    else:
        return convert_to_unicode(text)


def python2_3_convert_to_unicode(text):
    if sys.version_info >= (3, 0):
        return convert_to_unicode(text)
    else:
        return text


def convert_to_unicode(text):
    if isinstance(text, dict) or isinstance(text, DotDict):
        return {
            convert_to_unicode(key): convert_to_unicode(value)
            for key, value in list(text.items())
        }
    elif isinstance(text, list):
        return [convert_to_unicode(element) for element in text]
    elif isinstance(text, six.string_types):
        return text.encode("utf-8", errors="ignore")
    else:
        return text


def value_in_any_list_item(value, list_obj):
    if isinstance(list_obj, list):
        return len([item for item in list_obj if value.lower() in item.lower()]) > 0
    elif isinstance(list_obj, str):
        return value.lower() in list_obj.lower()
