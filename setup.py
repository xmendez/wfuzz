import os
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

docs_requires = [
    "Sphinx",
]

dev_requires = [
    'mock',
    'coverage',
    'codecov',
    'netaddr',
    'pip-tools',
    'flake8==3.8.3',
    'black==19.10b0;python_version>"3.5"',
]

install_requires = [
    'pycurl',
    'pyparsing<2.4.2;python_version<="3.4"',
    'pyparsing>2.4*;python_version>="3.5"',
    'future',
    'six',
    'configparser;python_version<"3.5"',
    'chardet',
    'pytest',
]


if sys.platform.startswith("win"):
    install_requires += ["colorama>=0.4.0"]


try:
    os.symlink('../../docs/user/advanced.rst', 'src/wfuzz/advanced.rst')
    setup(
        name="wfuzz",
        packages=find_packages(where='src'),
        package_dir={'wfuzz': 'src/wfuzz'},
        include_package_data=True,
        package_data={'wfuzz': ['*.rst']},
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
        license="GPLv2",
        install_requires=install_requires,
        extras_require={
            'dev': dev_requires,
            'docs': docs_requires,
        },
        python_requires=">=2.6",
        classifiers=(
            'Development Status :: 4 - Beta',
            'Natural Language :: English',
            'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
        ),
    )
finally:
    os.unlink('src/wfuzz/advanced.rst')
