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


#
# AFFLIB RELEASE SYSTEM V1.0 FOLLOWS
#

RELEASE_USER = simsong@
RELEASE_HOST = www.afflib.org
RELEASE_DIR  = afflib.org/

RELEASE_LOC  = $(RELEASE_DIR)/downloads/
VERSION_FN   = $(PACKAGE)_version.txt
RELEASE_PATH = $(RELEASE_LOC)/$(VERSION_FN)
RELEASE_SSH  = $(RELEASE_USER)$(RELEASE_HOST):$(RELEASE_LOC)
RELEASE_VER  = $(PACKAGE)-$(VERSION_FN)
RELEASEFN    = $(PACKAGE)-$(VERSION).tar.gz
PACKAGEFN    = $(PACKAGE).tar.gz


release:
	make check_release_version
	make dist
	make distcheck
	make the_release

check_release_version:
	@echo Checking version on server for $(VERSION_FN)
	@echo
	echo
	/bin/rm -f $(VERSION_FN)
	wget -q http://$(RELEASE_HOST)/downloads/$(VERSION_FN)
	@echo Version `cat $(VERSION_FN)` is on the server.
	@sh -c "if [ `cat $(VERSION_FN)` = $(RELEASEFN) ]; then echo ; echo ; echo $(RELEASE_VER) is already on the server; exit 1; fi"
	/bin/rm -f $(VERSION_FN)

the_release: 
	gpg --detach-sign $(RELEASEFN)
	scp $(RELEASEFN){,.sig} $(RELEASE_SSH)
	ssh $(RELEASE_HOST) 'cd $(RELEASE_LOC);/bin/rm $(PACKAGE).tar.gz;ln -s $(RELEASEFN) $(PACKAGEFN)'
	ssh $(RELEASE_HOST) 'echo $(RELEASEFN) > $(RELEASE_PATH)'
	@echo Release $(RELEASE_VER) uploaded to server



#
# END OF AFFLIB RELEASE SYSTEM
#