all: proto util merkletree client server

proto::
	cd proto && $(MAKE)

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
