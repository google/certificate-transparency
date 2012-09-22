VERSION=02
PREV=$(shell expr $(VERSION) - 1 | printf '%02d')
NAME=draft-laurie-pki-sunlight
BASE=$(NAME)-$(VERSION)
DIFF=$(NAME)-$(PREV)-$(VERSION)-diff.html

all: $(BASE).html $(BASE).txt $(DIFF)

$(BASE).html: sunlight.xml
	xml2rfc sunlight.xml $(BASE).html

$(BASE).txt: sunlight.xml
	xml2rfc sunlight.xml $(BASE).txt

$(DIFF): $(NAME)-$(PREV).txt $(BASE).txt
	rfcdiff --stdout $(NAME)-$(PREV).txt $(BASE).txt > $(DIFF)
