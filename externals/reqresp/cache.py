from collections import defaultdict

class HttpCache:
    def __init__(self):
	# cache control
	self.__cache_map = defaultdict(list)

    def _gen_cache_key(self, req):
	key = req.urlWithoutVariables

	dicc = {}

	for j in [i.name for i in req.getGETVars()]:
	    dicc[j] = True

	for j in [i.name for i in req.getPOSTVars()]:
	    dicc[j] = True

	# take URL parameters into consideration
	url_params = dicc.keys()
	url_params.sort()
	key += "-" + "-".join(url_params)

	return key

    def update_cache(self, req, category = 'default'):
	key = self._gen_cache_key(req)

	# first hit
	if not key in self.__cache_map:
	    self.__cache_map[key].append(category)
	    return True
	elif key in self.__cache_map and not category in self.__cache_map[key]:
	    self.__cache_map[key].append(category)
	    return True

	return False

    def msg_in_cache(self, req, category = 'default'):
	key = self._gen_cache_key(req)

	return key in self.__cache_map and category in self.__cache_map[key]

