#!/usr/bin/env python3
"""Wrapper so the tool runs from anywhere: python3 tools/corpus.py --help"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bpfkit.corpus import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
