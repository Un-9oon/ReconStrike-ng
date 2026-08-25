PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/reconstrike
DOCDIR ?= $(PREFIX)/share/doc/reconstrike

.PHONY: install uninstall

install:
	mkdir -p $(DESTDIR)$(SHAREDIR)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(DOCDIR)
	cp -r scanner/ $(DESTDIR)$(SHAREDIR)/
	cp reconstrike.py $(DESTDIR)$(SHAREDIR)/
	ln -sf $(SHAREDIR)/reconstrike.py $(DESTDIR)$(BINDIR)/reconstrike
	cp README.md LICENSE CHANGELOG.md $(DESTDIR)$(DOCDIR)/
	chmod +x $(DESTDIR)$(SHAREDIR)/reconstrike.py

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/reconstrike
	rm -rf $(DESTDIR)$(SHAREDIR)
	rm -rf $(DESTDIR)$(DOCDIR)
