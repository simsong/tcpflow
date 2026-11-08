# Makefile.am for tcpflow
# 
SUBDIRS = src doc tests
EXTRA_DIST = tcpflow.spec.in TODO.txt m4/ax_pthread.m4 \
	bootstrap.sh Makefile.ci .clang-tidy etc/Dockerfile.ci \
	scripts/ci.sh scripts/release.sh scripts/test-windows.ps1 \
	scripts/verify-authenticode.ps1 scripts/windows-deps.sh snap/snapcraft.yaml snap/fonts.conf \
	tests/test_ci_release.py doc/CI_CD.md doc/CI_CD_ANALYSIS.md
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall

renew:
	touch NEWS README AUTHORS ChangeLog stamp-h
	aclocal
	autoheader -f
	autoconf -f
	automake --add-missing -c

grenew:
	touch NEWS README AUTHORS ChangeLog stamp-h
	aclocal
	autoheader -f
	autoconf -f
	automake --add-missing -c


# For testing:
pdft:	
	(cd src;make tcpflow)
	/bin/rm -rf out
	src/tcpflow -a -o out -r /corp/nps/packets/2008-nitroba/nitroba.pcap -w out/extra.pcap
	open out/report.pdf

# Release publication is owned by the tag-triggered GitHub workflow.
# This local target validates the source archive without creating a tag.
.PHONY: release ci
release: distcheck
ci:
	$(MAKE) all
	$(MAKE) -j1 check

.PHONY: analyzer-build
analyzer-build: all
	$(MAKE) -C src analysis-tests
