all: govpn.info govpn.html

MAKEINFO ?= makeinfo

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.info: *.texi handshake.utxt
	$(MAKEINFO) -o govpn.info index.texi

govpn.html: *.texi handshake.utxt
	rm -f govpn.html/*.html
	$(MAKEINFO) --html \
		--css-include=style.css \
		--set-customization-variable SHOW_TITLE=0 \
		--set-customization-variable DATE_IN_HEADER=1 \
		-o govpn.html index.texi
