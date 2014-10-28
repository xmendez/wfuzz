from distutils.core import setup
import py2exe
import os

# 1.- You need to install the following in order to build wfuzz in windows:
# python 2.7 for x86
# http://newcenturycomputers.net/projects/wconio.html
# http://pycurl.sourceforge.net/download/
# http://sourceforge.net/projects/pyparsing/files/pyparsing/pyparsing-2.0.2/

# 2.- Run c:\Python27\python.exe setup.py py2exe

# 3.- wfuzz_windows directory is the one to be distributed.

# Problem is that plugins import modules that py2exe is not going to pick up,
# so they must be included here. Also, if new plugins add other imports afterwards, these
# are going to fail?

opts = {
    "py2exe": {
        "includes": "xml.dom.minidom,framework.plugins.api,pipes,sqlite3,WConio",
        "dist_dir": "wfuzz_windows",
    }
}

setup( name='wfuzz', options=opts,console=['wfuzz.py'])

# copying plugins directory
import shutil, errno
shutil.copytree("plugins", "wfuzz_windows//plugins")
shutil.copytree("wordlist", "wfuzz_windows//wordlist")
