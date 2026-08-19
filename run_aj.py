#!/usr/bin/env python3
"""Run AJLang .aj files: python run_aj.py file.aj"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ajlang import __main__

if __name__ == "__main__":
    __main__.main()
