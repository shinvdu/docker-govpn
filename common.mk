.PHONY: doc

LDFLAGS = -X cypherpunks.ru/govpn.Version=$(VERSION)
PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin
INFODIR = $(DESTDIR)$(PREFIX)/info
SHAREDIR = $(DESTDIR)$(PREFIX)/share/govpn
DOCDIR = $(DESTDIR)$(PREFIX)/share/doc/govpn

all: govpn-client govpn-server govpn-verifier

govpn-client:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/govpn/cmd/govpn-client

govpn-server:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/govpn/cmd/govpn-server

govpn-verifier:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/govpn/cmd/govpn-verifier

bench:
	GOPATH=$(GOPATH) go test -benchmem -bench . cypherpunks.ru/govpn/...

clean:
	rm -f govpn-client govpn-server govpn-verifier

doc:
	$(MAKE) -C doc

install: all doc
	mkdir -p $(BINDIR)
	cp -f govpn-client govpn-server govpn-verifier $(BINDIR)
	chmod 755 $(BINDIR)/govpn-client $(BINDIR)/govpn-server $(BINDIR)/govpn-verifier
	mkdir -p $(INFODIR)
	cp -f doc/govpn.info $(INFODIR)
	chmod 644 $(INFODIR)/govpn.info
	mkdir -p $(SHAREDIR)
	cp -f utils/newclient.sh $(SHAREDIR)
	chmod 755 $(SHAREDIR)/newclient.sh
	mkdir -p $(DOCDIR)
	cp -f -L AUTHORS INSTALL NEWS README README.RU THANKS $(DOCDIR)
	chmod 644 $(DOCDIR)/*

install-strip: install
	strip $(BINDIR)/govpn-client $(BINDIR)/govpn-server $(BINDIR)/govpn-verifier
