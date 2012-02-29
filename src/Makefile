all: merkletree client server

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
