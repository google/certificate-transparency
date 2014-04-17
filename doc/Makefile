VERSION=02
PREV=01
XML=rfc6962-bis.xml
NAME=draft-ietf-trans-rfc6962-bis
BASE=$(NAME)-$(VERSION)
DIFF=$(NAME)-$(PREV)-$(VERSION)-diff.html

all: $(BASE).html $(BASE).txt $(DIFF)

.DELETE_ON_ERROR:

$(BASE).html: $(XML)
	xml2rfc --html -o $(BASE).html $(XML)

$(BASE).txt: $(XML)
	xml2rfc --text -o $(BASE).txt $(XML)

$(DIFF): $(NAME)-$(PREV).txt $(BASE).txt
	rfcdiff --stdout $(NAME)-$(PREV).txt $(BASE).txt > $(DIFF)
