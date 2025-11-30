

# this file is part of the "snorter" project. 
# Copyright (C) 2004 by Jean Philippe GUILLEMIN <jp.guillemin@free.fr>
# license: This software is under GPL version 2 of license
# date: 08 2004
# rev: 2.0


ROOT = /opt/snorter
SOURCEPATH = .
CONFIGPATH = /etc/snorter
BIN=snorter.sh
BINPATH=/usr/sbin

certname = snorter
life = 730
keylength = 1024
listen_port = 666
listen_ip = 127.0.0.1

KEY_REPOSITORY = $(CONFIGPATH)/ssl_key
SSL_PROGRAM = /usr/bin/openssl


install : dir snorter selfsign perlgd conf run by

dir :
	mkdir -p $(ROOT)
	mkdir -p $(CONFIGPATH)
	mkdir -p $(KEY_REPOSITORY)



snorter :
	@echo "snorter install"
	chmod 755 $(ROOT)
	cp -pf $(SOURCEPATH)/miniserv.pl $(ROOT)/
	cp -rpf $(SOURCEPATH)/webroot $(ROOT)/
	cp -pf $(SOURCEPATH)/mime.types $(CONFIGPATH)/
	


uninstall : 
	rm -rf $(ROOT)
	rm -rf $(CONFIGPATH)
	rm -rf $(KEY_REPOSITORY)
	rm -f $(BINPATH)/$(BIN)

perlgd: 
	@echo "perlgd modules install"
	@if test ! -d perlmod/GD-2.11 ; then \
	echo 'missing GD-2.11'; \
	else ./install_libs ./perlmod/GD-2.11; fi
	@if test ! -d perlmod/GDGraph-1.43 ; then \
	echo 'missing GDGraph-1.43'; \
	else ./install_libs ./perlmod/GDGraph-1.43; fi
	@if test ! -d perlmod/GDTextUtil-0.86 ; then \
	echo 'missing GDTextUtil-0.86'; \
	else ./install_libs ./perlmod/GDTextUtil-0.86; fi

keygen:
	@if test -f $(KEY_REPOSITORY)/$(certname).key ; then \
		echo 'key $(KEY_REPOSITORY)/$(certname).key already exist'; \
		echo '-----'; \
	else \
		echo 'Generating RSA key $(KEY_REPOSITORY)/$(certname).key'; \
		$(SSL_PROGRAM) genrsa -out $(KEY_REPOSITORY)/$(certname).key $(keylength); \
		echo '-----'; fi

csrgen: keygen
	@if test -f $(KEY_REPOSITORY)/$(certname).csr ; then \
		echo 'Cert request $(KEY_REPOSITORY)/$(certname).csr already exist'; \
		echo '-----'; \
	else \
		$(SSL_PROGRAM) req -new -key $(KEY_REPOSITORY)/$(certname).key -out $(KEY_REPOSITORY)/$(certname).csr; \
		echo '-----'; fi

selfsign: keygen csrgen
	@if test -f $(KEY_REPOSITORY)/$(certname).crt ; then \
		echo 'Certificate $(KEY_REPOSITORY)/$(certname).crt already exist'; \
		echo '-----'; \
	else \
		echo 'Generating certficate $(KEY_REPOSITORY)/$(certname).crt'; \
		$(SSL_PROGRAM) req -in $(KEY_REPOSITORY)/$(certname).csr -key $(KEY_REPOSITORY)/$(certname).key -x509 -days $(life) -out $(KEY_REPOSITORY)/$(certname).crt; \
		cat $(KEY_REPOSITORY)/$(certname).crt >> $(KEY_REPOSITORY)/$(certname).pem; \
		cat $(KEY_REPOSITORY)/$(certname).key >> $(KEY_REPOSITORY)/$(certname).pem; \
		echo '-----'; fi

		
conf:
	@echo 'port=$(listen_port)' >> $(CONFIGPATH)/snorter.conf
	@echo 'addtype_pl=internal/cgi' >> $(CONFIGPATH)/snorter.conf
	@echo 'realm=Miniserv Perl Web Server' >> $(CONFIGPATH)/snorter.conf
	@echo 'logfile=/var/log/miniserv.log' >> $(CONFIGPATH)/snorter.conf
	@echo 'errorlog=/var/log/miniserv.error' >> $(CONFIGPATH)/snorter.conf
	@echo 'pidfile=/var/log/miniserv.pid' >> $(CONFIGPATH)/snorter.conf
	@echo 'keyfile=$(KEY_REPOSITORY)/$(certname).pem' >> $(CONFIGPATH)/snorter.conf
	@echo 'logtime=600' >> $(CONFIGPATH)/snorter.conf
	@echo 'ssl=1' >> $(CONFIGPATH)/snorter.conf
	@echo 'listen=$(listen_ip):$(listen_port)' >> $(CONFIGPATH)/snorter.conf
	@echo 'log=1' >> $(CONFIGPATH)/snorter.conf
	@echo 'syslog=1' >> $(CONFIGPATH)/snorter.conf
	@echo 'session=1' >> $(CONFIGPATH)/snorter.conf
	@echo 'root=$(ROOT)/webroot' >> $(CONFIGPATH)/snorter.conf
	@echo 'mimetypes=$(CONFIGPATH)/mime.types' >> $(CONFIGPATH)/snorter.conf
	chmod 644 $(CONFIGPATH)/snorter.conf


run:
	@echo '#!/bin/bash' >> $(BINPATH)/$(BIN)
	@echo 'exec $(ROOT)/miniserv.pl $(CONFIGPATH)/snorter.conf' >> $(BINPATH)/$(BIN)
	chmod 711 $(BINPATH)/$(BIN)

	
by :
	@echo "see http://shweps.free.fr/snorter.html for information : have fun :))"

