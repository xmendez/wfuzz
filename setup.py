import sys
import re
from setuptools import setup, find_packages

with open("README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


version = re.search(
    r'^__version__\s*=\s*"(.*)"',
    open('src/wfuzz/__init__.py').read(),
    re.M
).group(1)


dev_requires = [
    'mock',
    'netaddr',
    'pip-tools',
]

install_requires = [
    'pycurl<=7.43.0.3',
    'pyparsing',
    'future',
    'six',
    'configparser;python_version<"3.5"',
    'chardet',
]

if sys.platform.startswith("win"):
    install_requires += ["colorama"]

setup(
    name="wfuzz",
    include_package_data=True,
    data_files=[('docs/user', ['docs/user/advanced.rst'])],
    packages=find_packages(where='src'),
    package_dir={'wfuzz': 'src/wfuzz'},
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
    version=version,
    description="Wfuzz - The web fuzzer",
    long_description=long_descr,
    author="Xavi Mendez (@x4vi_mendez)",
    author_email="xmendez@edge-security.com",
    url="http://wfuzz.org",
    install_requires=install_requires,
    extras_require={
        'dev': dev_requires,
    },
    python_requires=">=2.6",
    classifiers=(
        'Development Status :: 4 - Beta',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ),
)
