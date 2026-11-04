#!/bin/bash
# Self-contained assertions; no pre-existing /tmp files required.
set -eu
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -p test_awdp_runtime.py -v
