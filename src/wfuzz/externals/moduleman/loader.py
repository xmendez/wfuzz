import inspect
import logging
import imp
import os.path

class IModuleLoader:
    def __init__(self, **params):
	self.set_params(**params)

    def set_params(self, **params):
	raise NotImplemented	

    def load(self, registrant):
	raise NotImplemented	

class FileLoader(IModuleLoader):
    def __init__(self, **params):
	IModuleLoader.__init__(self, **params)
	self.__logger = logging.getLogger("libraries.FileLoader")

    def set_params(self, **params):
	if not "base_path" in params:
	    return
	elif not "filename" in params:
	    return

	self.filename = params["filename"]
	self.base_path = params["base_path"]
	if self.base_path.endswith('/'): self.base_path = self.base_path[:-1]

    def load(self, registrant):
	self.module_registrant = registrant

	self._load_py_from_file(os.path.join(self.base_path, self.filename))

    def _build_id(self, filename, objname):
	filepath, filename = os.path.split(filename)

	fn = os.path.splitext(filename)[0]
        relative_path = os.path.relpath(filepath, os.path.join(self.base_path, self.base_dir))
	identifier = relative_path + '/' + objname
	if identifier.startswith('./'): identifier = identifier[2:]

	return identifier
	
    def _load_py_from_file(self, filename):
	"""
	Opens "filename", inspects it and calls the registrant
	"""
	self.__logger.debug('__load_py_from_file. START, file=%s' % (filename,))

	dirname, filename = os.path.split(filename)
	fn = os.path.splitext(filename)[0]
	exten_file = None
	module = None

	try:
	    exten_file, filename, description = imp.find_module(fn, [dirname])
	    module = imp.load_module(fn, exten_file, filename, description)
	except ImportError, msg:
	    self.__logger.critical('__load_py_from_file. Filename: %s Exception, msg=%s' % (filename, msg))
	    #raise msg
	    pass
	except SyntaxError, msg:
	    # incorrect python syntax in file
	    self.__logger.critical('__load_py_from_file. Filename: %s Exception, msg=%s' % (filename, msg))
	    #raise msg
	    pass
	finally:
	    if exten_file: exten_file.close()

	if module is None:
	    return

	for objname in dir(module):
	    obj = getattr(module, objname)
	    self.__logger.debug('__load_py_from_file. inspecting=%s' % (objname,))
	    if inspect.isclass(obj):
		if '__PLUGIN_MODULEMAN_MARK' in dir(obj):
		    if self.module_registrant:
			self.module_registrant.register(self._build_id(filename, objname), obj)

	self.__logger.debug('__load_py_from_file. END, loaded file=%s' % (filename,))

class DirLoader(FileLoader):
    def __init__(self, **params):
	FileLoader.__init__(self, **params)
	self.__logger = logging.getLogger("libraries.DirLoader")
	
    def set_params(self, **params):
	if not "base_dir" in params:
	    return
	elif not "base_path" in params:
	    return

	self.base_dir = params["base_dir"]
	self.base_path = params["base_path"]
	if self.base_path.endswith('/'): self.base_path = self.base_path[:-1]

    def load(self, registrant):
	self.module_registrant = registrant
	self.structure = self.__load_all(self.base_dir)
	
    def __load_all(self, dir_name):
	"""
	loads all plugins and creates a loaded list of scripts from directory plugins like:
	[ ( category,[script1, script2,...] ), (category2,[script1, (subcategory,[script1,script2]),...]) ]
	"""
	walked = []

	current = os.path.join(self.base_path, dir_name)
	if os.path.isdir(current):
	    l = self.__walk_dir_tree(current)
	    walked.append((current, l))
	    if self.module_registrant:
		self.module_registrant.end_loading()

	return walked

    def __walk_dir_tree(self, dirname):
	l=[]

	self.__logger.debug('__walk_dir_tree. START dir=%s', dirname)

        for f in os.listdir(dirname):
	    current = os.path.join(dirname, f)
	    if os.path.isfile(current) and f.endswith("py"):
		if self.module_registrant:
		    self._load_py_from_file(current)

		l.append(current)
	    elif os.path.isdir(current):
		ret = self.__walk_dir_tree(current)
		if ret: l.append( (f, ret) )

	return l

if __name__ == '__main__':

    from registrant import BRegistrant

    logging.basicConfig(level = logging.DEBUG,
		    format = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
		    datefmt = '%m-%d %H:%M',
		    filename = "/tmp/log",
		    filemode = 'a')

    fl = FileLoader(**{"filename": "1.py", "base_path": "." })

    br = BRegistrant(fl)

    print br.get_plugins_ext()
    print br.get_plugins()

    print br.get_plugins_ext("default")
    print br.get_plugins_ext("aggressive")

    print br.get_plugins_names()
    print br.get_plugins_names("default")
    print br.get_plugins_names("aggressive")
    print br.get_plugins_ids("aggressive")

