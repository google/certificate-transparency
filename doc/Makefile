VERSION=03
PREV=02
NAME=draft-laurie-pki-sunlight
BASE=$(NAME)-$(VERSION)
DIFF=$(NAME)-$(PREV)-$(VERSION)-diff.html

all: $(BASE).html $(BASE).txt $(DIFF)

.DELETE_ON_ERROR:

$(BASE).html: sunlight.xml
	xml2rfc sunlight.xml $(BASE).html

$(BASE).txt: sunlight.xml
	xml2rfc sunlight.xml $(BASE).txt

$(DIFF): $(NAME)-$(PREV).txt $(BASE).txt
	rfcdiff --stdout $(NAME)-$(PREV).txt $(BASE).txt > $(DIFF)
