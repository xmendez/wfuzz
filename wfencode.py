#!/usr/bin/env python

import sys
import os

sys.path.insert(0, os.path.abspath('src'))

from wfuzz.wfuzz import main_encoder

if __name__ == '__main__':
    main_encoder()
