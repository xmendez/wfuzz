from collections import defaultdict

class HttpCache:
    def __init__(self):
	# cache control
	self.__cache_map = defaultdict(list)

    def update_cache(self, req, category = 'default'):
	key = req.to_cache_key()

	# first hit
	if not key in self.__cache_map:
	    self.__cache_map[key].append(category)
	    return True
	elif key in self.__cache_map and not category in self.__cache_map[key]:
	    self.__cache_map[key].append(category)
	    return True

	return False

    def msg_in_cache(self, req, category = 'default'):
	key = req.to_cache_key()

	return key in self.__cache_map and category in self.__cache_map[key]

