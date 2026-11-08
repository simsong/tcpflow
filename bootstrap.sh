#!/bin/bash
# Generate the Autotools build system for a repository checkout.
# be13_api and dfxml are vendored; only http-parser is a Git submodule.
# Initialize that pinned submodule only when its sources are missing.
# autoreconf installs portable helper scripts and expands configure.ac.
# Source releases already contain configure and do not need this script.
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -f src/http-parser/http_parser.c ]]; then
    git submodule update --init src/http-parser
fi
autoreconf --force --install
