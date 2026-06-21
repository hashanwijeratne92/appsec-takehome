#!/usr/bin/env bash

set -u

python3 scripts/scan_secrets.py
SCAN_EXIT=$?

python3 scripts/triage_report.py

exit $SCAN_EXIT
