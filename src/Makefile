all: proto util merkletree log client server

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

log::
	cd log && $(MAKE)

# TODO: make it easier to detect any test failures.
test::
	cd merkletree && $(MAKE) test
	cd log && $(MAKE) test
	cd proto && $(MAKE) test
	cd test && $(MAKE) test

clean:
	cd client && $(MAKE) clean
	cd server && $(MAKE) clean
	cd merkletree && $(MAKE) clean
	cd util && $(MAKE) clean
	cd log && $(MAKE) clean
	cd proto && $(MAKE) clean
