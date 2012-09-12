VERSION=00
BASE=draft-laurie-pki-sunlight-$(VERSION)

all: $(BASE).html $(BASE).txt

$(BASE).html: sunlight.xml
	xml2rfc sunlight.xml $(BASE).html

$(BASE).txt: sunlight.xml
	xml2rfc sunlight.xml $(BASE).txt
