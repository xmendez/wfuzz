import re
import os

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

    tokenizer = re.compile('"|(/\*)|(\*/)|(//)|\n|\r')
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
            index -= 1 # include " character in next catch
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
	#try:
	if not class_.hasInstance():
	    class_.instance = super(Singleton, class_).__call__(*args, **kwargs)
	return class_.instance
	#except Exception, e:
	#    error_type, error_value, trbk = sys.exc_info()
	#    tb_list = traceback.format_tb(trbk, 6)    
	#    s = "Error: %s \nDescription: %s \nTraceback:" % (error_type.__name__, error_value)
	#    for i in tb_list:
	#	s += "\n" + i

	#    print s
	#    return None

    def deleteInstance(class_):
        ''' Delete the (only) instance. This method is mainly for unittests so
            they can start with a clean slate. '''
        if class_.hasInstance():
            del class_.instance

    def hasInstance(class_):
        ''' Has the (only) instance been created already? '''
        return hasattr(class_, 'instance')


def get_home(check = False, directory = None):
    path = os.path.join(os.path.expanduser("~"), ".wfuzz")
    if check:
        if not os.path.exists(path):
            os.makedirs(path)

    return os.path.join(path, directory) if directory else path

def get_path(directory = None):
    abspath = os.path.abspath(__file__)
    ret = os.path.dirname(abspath)

    return os.path.join(ret, directory) if directory else ret


def find_file_in_paths(name, path):
    for root, dirs, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)

    return None
