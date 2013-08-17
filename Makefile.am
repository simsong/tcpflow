# Makefile.am for tcpflow
# 
SUBDIRS = src doc tests
EXTRA_DIST = tcpflow.spec.in TODO.txt m4/ax_pthread.m4
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

#
# AFFLIB RELEASE SYSTEM V1.0 FOLLOWS
#

RELEASE_USER = simsong@
RELEASE_HOST = www.digitalcorpora.org
RELEASE_DIR  = digitalcorpora.org/

RELEASE_LOC  = $(RELEASE_DIR)/downloads/
VERSION_FN   = $(PACKAGE)_version.txt
RELEASE_PATH = $(RELEASE_LOC)/$(VERSION_FN)
RELEASE_SSH  = $(RELEASE_USER)$(RELEASE_HOST):$(RELEASE_LOC)


release:
	make dist
	make distcheck
	make the_release

the_release: $(RELEASEFN)
	gpg --detach-sign $(RELEASEFN)
	@echo Release $(RELEASE_VER) uploaded to server

tcpflow32.exe:
	mingw32-configure
	make clean
	make 

tcpflow64.exe:
	mingw64-configure
	make clean
	make 

FN=$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
winrelease:
	/bin/rm -f tcpflow*.exe $(FN).zip
	make tcpflow32.exe
	mv -f src/tcpflow.exe tcpflow32.exe
	make tcpflow64.exe
	mv -f src/tcpflow.exe tcpflow64.exe
	zip $(FN).zip tcpflow*.exe


pull:
	git pull
	(cd src/dfxml;git pull)
	(cd src/be13_api;git pull)
#
# END OF AFFLIB RELEASE SYSTEM
#
