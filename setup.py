import re
from setuptools import setup, find_packages

with open("README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('wfuzz/__init__.py').read(),
    re.M
    ).group(1)
 
 
setup(
    name = "wfuzz",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'wfuzz = wfuzz.wfuzz:main',
            'wfpayload = wfuzz.wfuzz:main_filter',
            'wfencode = wfuzz.wfuzz:main_encoder',
        ],
        'gui_scripts': [
            'wxfuzz = wfuzz.wfuzz:main_gui',
        ]
    },
    version = version,
    description = "Wfuzz - The web fuzzer",
    long_description = long_descr,
    author = "Xavi Mendez (@x4vi_mendez)",
    url = "http://wfuzz.org",
    )
