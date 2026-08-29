PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/reconstrike-ng
DOCDIR ?= $(PREFIX)/share/doc/reconstrike-ng

.PHONY: install uninstall test lint dev-setup

dev-setup:
	pip install -r requirements.txt
	pip install pytest pytest-cov flake8

test: dev-setup
	python -m pytest tests/ -v --tb=short

lint:
	flake8 scanner/ reconstrike_ng.py --max-line-length=120 --ignore=E501,W503,W504,E303,E302

install:
	mkdir -p $(DESTDIR)$(SHAREDIR)
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(DOCDIR)
	cp -r scanner/ $(DESTDIR)$(SHAREDIR)/
	cp reconstrike_ng.py $(DESTDIR)$(SHAREDIR)/
	ln -sf $(SHAREDIR)/reconstrike_ng.py $(DESTDIR)$(BINDIR)/reconstrike-ng
	cp README.md LICENSE CHANGELOG.md $(DESTDIR)$(DOCDIR)/
	chmod +x $(DESTDIR)$(SHAREDIR)/reconstrike_ng.py

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/reconstrike-ng
	rm -rf $(DESTDIR)$(SHAREDIR)
	rm -rf $(DESTDIR)$(DOCDIR)
