#!/usr/bin/env python3
"""Compatibility entry point for the hardened FortiGate filesystem hash checker."""

import sys

from fs_hash_checker.cli import main


if __name__ == "__main__":
    sys.exit(main())
