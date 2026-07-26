#!/usr/bin/env python3
"""AutoFuzz entrypoint.

    python autofuzz.py -i domains.txt
    python autofuzz.py -d https://api.example.com --threads 50 --html --json

See README.md for prerequisites and the authorized-use notice.
"""
from autofuzz.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
