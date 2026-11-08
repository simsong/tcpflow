#!/bin/sh
# Run the security regression through the configured build's tcpflow.
# Automake supplies source paths for checkout and distribution builds.
# The Python driver creates isolated fixtures and checks real behavior.
# A failure propagates to make check and the native/sanitizer CI jobs.
# Temporary captures and output files are removed by the driver.
. "$srcdir/test-subs.sh"
python3 "$srcdir/test-wifi-bounds.py" "$TCPFLOW"
