#!/usr/bin/env python3
"""Wrapper so the tool runs from anywhere: python3 tools/capread.py --help"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpfkit.capread import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
