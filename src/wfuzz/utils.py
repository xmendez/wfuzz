import re
import os
import sys
import six
from chardet.universaldetector import UniversalDetector


def json_minify(string, strip_space=True):
    '''
    Created on 20/01/2011
    v0.2 (C) Gerald Storer
    MIT License
    Based on JSON.minify.js:
    https://github.com/getify/JSON.minify
    Contributers:
    - Pradyun S. Gedam (conditions and variable names changed)
    '''

    tokenizer = re.compile(r'"|(/\*)|(\*/)|(//)|\n|\r')
    end_slashes_re = re.compile(r'(\\)*$')

    in_string = False
    in_multi = False
    in_single = False

    new_str = []
    index = 0

    for match in re.finditer(tokenizer, string):

        if not (in_multi or in_single):
            tmp = string[index:match.start()]
            if not in_string and strip_space:
                # replace white space as defined in standard
                tmp = re.sub('[ \t\n\r]+', '', tmp)
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
            if val == '/*':
                in_multi = True
            elif val == '//':
                in_single = True
        elif val == '*/' and in_multi and not (in_string or in_single):
            in_multi = False
        elif val in '\r\n' and not (in_multi or in_string) and in_single:
            in_single = False
        elif not ((in_multi or in_single) or (val in ' \r\n\t' and strip_space)):
            new_str.append(val)

    new_str.append(string[index:])
    return ''.join(new_str)


class Singleton(type):
    ''' Singleton metaclass. Use by defining the metaclass of a class Singleton,
        e.g.: class ThereCanBeOnlyOne:
                  __metaclass__ = Singleton
    '''

    def __call__(class_, *args, **kwargs):
        if not class_.hasInstance():
            class_.instance = super(Singleton, class_).__call__(*args, **kwargs)
        return class_.instance

    def deleteInstance(class_):
        ''' Delete the (only) instance. This method is mainly for unittests so
            they can start with a clean slate. '''
        if class_.hasInstance():
            del class_.instance

    def hasInstance(class_):
        ''' Has the (only) instance been created already? '''
        return hasattr(class_, 'instance')


def get_home(check=False, directory=None):
    path = os.path.join(os.path.expanduser("~"), ".wfuzz")
    if check:
        if not os.path.exists(path):
            os.makedirs(path)

    return os.path.join(path, directory) if directory else path


def get_path(directory=None):
    abspath = os.path.abspath(__file__)
    ret = os.path.dirname(abspath)

    return os.path.join(ret, directory) if directory else ret


def find_file_in_paths(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)

    return None


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
    if isinstance(text, dict):
        return {convert_to_unicode(key): convert_to_unicode(value) for key, value in list(text.items())}
    elif isinstance(text, list):
        return [convert_to_unicode(element) for element in text]
    elif isinstance(text, six.string_types):
        return text.encode("utf-8", errors='ignore')
    else:
        return text


def open_file_detect_encoding(file_path):
    def detect_encoding(file_path):
        detector = UniversalDetector()
        detector.reset()

        with open(file_path, mode='rb') as file_to_detect:
            for line in file_to_detect:
                detector.feed(line)
                if detector.done:
                    break
        detector.close()

        return detector.result

    if sys.version_info >= (3, 0):
        return open(file_path, "r", encoding=detect_encoding(file_path).get('encoding', 'utf-8'))
    else:
        return open(file_path, "r")
