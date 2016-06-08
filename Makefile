#!/bin/bin/make -f

build:

install:
	@echo "Installing into $(DESTDIR)"
	# create necessary directories
	install -d $(DESTDIR)/etc/oipf/conf.d
	install -d $(DESTDIR)/etc/oipf/rules.d
	install -d $(DESTDIR)/usr/sbin
	install -d $(DESTDIR)/usr/share/oipf/libs.d
	install -d $(DESTDIR)/var/lib/oipf/iptdumps
	install -d $(DESTDIR)/var/lib/oipf/tmp
	# install files
	touch $(DESTDIR)/etc/oipf/conf.d/.placeholder
	touch $(DESTDIR)/etc/oipf/rules.d/.placeholder
	touch $(DESTDIR)/usr/share/oipf/libs.d/.placeholder
	-install -m 0644 firewall/conf.d/* $(DESTDIR)/etc/oipf/conf.d/
	-install -m 0644 firewall/rules.d/* $(DESTDIR)/etc/oipf/rules.d/
	-install -m 0644 firewall/libs.d/* $(DESTDIR)/usr/share/oipf/libs.d
	install -m 0644 firewall/base-functions.fwl $(DESTDIR)/usr/share/oipf/
	install -m 0644 firewall/oipf.conf $(DESTDIR)/etc/oipf/oipf.conf
	install -m 0755 firewall/oipf.sh $(DESTDIR)/usr/sbin/oipf


.PHONY: install
