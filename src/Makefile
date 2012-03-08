all: util merkletree client server

util::
	cd util && $(MAKE)

client::
	cd client && $(MAKE)

server::
	cd server && $(MAKE)

merkletree::
	cd merkletree && $(MAKE)

clean:
	cd client && $(MAKE) clean
	cd server && $(MAKE) clean
	cd merkletree && $(MAKE) clean
	cd util && $(MAKE) clean
