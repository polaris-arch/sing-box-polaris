#!/usr/bin/env python3
"""Apply reviewed unsigned and libbox compatibility inputs; never sign or publish."""
import sys
from client_source import apply

if __name__ == '__main__':
    apply(sys.argv[1], unsigned=True)
