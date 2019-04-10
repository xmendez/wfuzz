import re
import os
import sys
import six
from threading import Lock
import functools

from chardet.universaldetector import UniversalDetector
import chardet
from .exception import FuzzExceptInternalError

allowed_fields = [
    "description",
    "nres",
    "code",
    "chars",
    "lines",
    "words",
    "md5",
    "l",
    "h",
    "w",
    "c",
    "history",
    "plugins",

    "url",
    "content",

    "history.url",
    "history.method",
    "history.scheme",
    "history.host",
    "history.content",
    "history.raw_content"
    "history.is_path",
    "history.pstrip",
    "history.cookies",
    "history.headers",
    "history.params",

    "r",
    "r.reqtime",
    "r.url",
    "r.method",
    "r.scheme",
    "r.host",
    "r.content",
    "r.raw_content"
    "r.is_path",
    "r.pstrip",
    "r.cookies.",
    "r.headers.",
    "r.params.",
]


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


class FileDetOpener:
    typical_encodings = [
        'UTF-8',
        'ISO-8859-1',
        'Windows-1251',
        'Shift JIS',
        'Windows-1252',
        'GB2312',
        'EUC-KR',
        'EUC-JP',
        'GBK',
        'ISO-8859-2',
        'Windows-1250',
        'ISO-8859-15',
        'Windows-1256',
        'ISO-8859-9',
        'Big5',
        'Windows-1254',
    ]

    def __init__(self, file_path, encoding=None):
        self.cache = []
        self.file_des = open(file_path, mode='rb')
        self.det_encoding = encoding
        self.encoding_forced = False

    def close(self):
        self.file_des.close()

    def reset(self):
        self.file_des.seek(0)

    def __iter__(self):
        return self

    def __next__(self):
        decoded_line = None
        line = None
        last_error = None

        while decoded_line is None:

            while self.det_encoding is None:
                detect_encoding = self.detect_encoding().get('encoding', 'utf-8')
                self.det_encoding = detect_encoding if detect_encoding is not None else 'utf-8'

            if line is None:
                if self.cache:
                    line = self.cache.pop()
                else:
                    line = next(self.file_des)
                    if not line:
                        raise StopIteration

            try:
                decoded_line = line.decode(self.det_encoding)
            except UnicodeDecodeError:
                if last_error is not None and last_error:
                    self.det_encoding = last_error.pop()
                elif last_error is None and not self.encoding_forced:
                    last_error = list(reversed(self.typical_encodings))
                    last_error.append(chardet.detect(line).get('encoding'))
                elif not last_error:
                    raise FuzzExceptInternalError("Unable to decode wordlist file!")

                decoded_line = None

        return decoded_line

    def detect_encoding(self):
        detector = UniversalDetector()
        detector.reset()

        for line in self.file_des:
            detector.feed(line)
            self.cache.append(line)
            if detector.done:
                break

        detector.close()

        return detector.result

    next = __next__  # for Python 2


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


class MyCounter:
    def __init__(self, count=0):
        self._count = count
        self._mutex = Lock()

    def inc(self):
        return self._operation(1)

    def dec(self):
        return self._operation(-1)

    def _operation(self, dec):
        with self._mutex:
            self._count += dec
            return self._count

    def __call__(self):
        with self._mutex:
            return self._count


def _check_allowed_field(attr):
    if [field for field in allowed_fields if attr.startswith(field)]:
        return True
    return False


def _get_alias(attr):
    attr_alias = {
        'l': 'lines',
        'h': 'chars',
        'w': 'words',
        'c': 'code',
        'r': 'history',
    }

    if attr in attr_alias:
        return attr_alias[attr]

    return attr


def rsetattr(obj, attr, new_val, operation):
    if not _check_allowed_field(attr):
        raise AttributeError("Unknown field {}".format(attr))

    pre, _, post = attr.rpartition('.')

    pre_post = None
    if len(attr.split('.')) > 3:
        pre_post = post
        pre, _, post = pre.rpartition('.')

    post = _get_alias(post)

    try:
        obj_to_set = rgetattr(obj, pre) if pre else obj
        prev_val = rgetattr(obj, attr)
        if pre_post is not None:
            prev_val = DotDict({pre_post: prev_val})

        if operation is not None:
            val = operation(prev_val, new_val)
        else:
            if isinstance(prev_val, DotDict):
                val = {k: new_val for k, v in prev_val.items()}
            else:
                val = new_val

        return setattr(obj_to_set, post, val)
    except AttributeError:
        raise AttributeError("rsetattr: Can't set '{}' attribute of {}.".format(post, obj_to_set.__class__))


def rgetattr(obj, attr, *args):
    def _getattr(obj, attr):
        attr = _get_alias(attr)
        try:
            return getattr(obj, attr, *args)
        except AttributeError:
            raise AttributeError("rgetattr: Can't get '{}' attribute from '{}'.".format(attr, obj.__class__))

    if not _check_allowed_field(attr):
        raise AttributeError("Unknown field {}".format(attr))

    return functools.reduce(_getattr, [obj] + attr.split('.'))


class DotDict(dict):
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __getattr__(*args):
        if args[1] not in args[0]:
            raise KeyError("DotDict: Non-existing field {}".format(args[1]))

        # python 3 val = dict.get(*args, None)
        val = dict.get(*args)
        return DotDict(val) if type(val) is dict else val
        # return DotDict(val) if type(val) is dict else DotDict({args[1]: val})

    def __add__(self, other):
        if isinstance(other, str):
            return DotDict({k: v + other for k, v in self.items() if v})
        elif isinstance(other, DotDict):
            # python 3 return DotDict({**self, **other})
            new_dic = DotDict(self)
            new_dic.update(other)
            return new_dic

    def __radd__(self, other):
        if isinstance(other, str):
            return DotDict({k: other + v for k, v in self.items() if v})


def value_in_any_list_item(value, list_obj):
    if isinstance(list_obj, list):
        return len([item for item in list_obj if value.lower() in item.lower()]) > 0
    elif isinstance(list_obj, str):
        return value.lower() in list_obj.lower()
