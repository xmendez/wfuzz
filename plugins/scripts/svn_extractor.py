from urlparse import urlparse, urljoin

from framework.plugins.api import DiscoveryPlugin
from framework.core.myexception import FuzzException
from externals.moduleman.plugin import moduleman_plugin

import tempfile
import sqlite3

@moduleman_plugin
class svn_extractor(DiscoveryPlugin):
    name = "svn_extractor"
    description = "Parses .svn/entries file. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def validate(self, fuzzresult):
	return fuzzresult.url.find(".svn/entries") > 0 and fuzzresult.code == 200

    def readsvn(self, content):
	'''
	Function shamesly copied (and adapted) from https://github.com/anantshri/svn-extractor/
	Credit (C) Anant Shrivastava http://anantshri.info
	'''
	old_line = ""
	file_list = []
	dir_list = []
	author_list = []

	for a in content.splitlines():
	    #below functionality will find all usernames from svn entries file
	    if (a == "has-props"):
		if not old_line in author_list: author_list.append(old_line)
	    if (a == "file"):
		if not old_line in file_list: file_list.append(old_line)
	    if (a == "dir"):
		if old_line != "":
		    dir_list.append(old_line)
	    old_line = a
	return file_list, dir_list, author_list

    def process(self, fuzzresult):
	base_url = fuzzresult.url

	file_list, dir_list, author_list = self.readsvn(fuzzresult.history.fr_content())

	if author_list:
	    self.add_result("SVN authors: %s" % ', '.join(author_list))

	for f in file_list:
	    u = urljoin(base_url.replace("/.svn/", "/"), f)
	    if not self.blacklisted_extension(u):
		self.queue_url(u)

	for d in dir_list:
	    self.queue_url(urljoin(base_url.replace("/.svn/", "/"), d) + "/.svn/entries")


@moduleman_plugin
class wcdb_extractor(DiscoveryPlugin):
    name = "wc_extractor"
    description = "Parses subversion's wc.db file. Optional: discovery.bl=\".txt,.gif\""
    category = ["default", "active", "discovery"]
    priority = 99

    def validate(self, fuzzresult):
	return fuzzresult.url.find(".svn/wc.d") > 0 and fuzzresult.code == 200

    def readwc(self, content):
	'''
	Function shamesly copied (and adapted) from https://github.com/anantshri/svn-extractor/
	Credit (C) Anant Shrivastava http://anantshri.info
	'''
	author_list = []
	list_items = None
	(fd, filename) = tempfile.mkstemp()

	with open(filename,"wb") as f:
	    f.write(content)

	conn = sqlite3.connect(filename)
	c = conn.cursor()
	try:
	    c.execute('select local_relpath, ".svn/pristine/" || substr(checksum,7,2) || "/" || substr(checksum,7) || ".svn-base" as alpha from NODES where kind="file";')
	    list_items = c.fetchall()
	    #below functionality will find all usernames who have commited atleast once.
	    c.execute('select distinct changed_author from nodes;')
	    author_list = [r[0] for r in c.fetchall()]
	    c.close()
	except Exception,e:
	    raise FuzzException(FuzzException.FATAL, "Error reading wc.db, either database corrupt or invalid file")

	return author_list, list_items

    def process(self, fuzzresult):
	author_list, list_items = self.readwc(fuzzresult.history.fr_content())

	if author_list:
	    self.add_result("SVN authors: %s" % ', '.join(author_list))

	if list_items:
	    for f, pristine in list_items:
		u = urljoin(fuzzresult.url.replace("/.svn/wc.db", "/"), f)
		if not self.blacklisted_extension(u):
		    self.add_result("SVN %s source code in %s" % (f, pristine))
		    self.queue_url(u)



