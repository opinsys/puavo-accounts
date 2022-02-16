prefix ?= /var/app
sysconfdir = /etc
installdir = $(prefix)/puavo-accounts

RUBY = /usr/bin/ruby
BUNDLE = $(RUBY) /usr/bin/bundle

.PHONY: build
build:
	$(BUNDLE) config set --local deployment true
	$(BUNDLE) install

.PHONY: update-gemfile-lock
update-gemfile-lock: clean
	rm -f Gemfile.lock
	GEM_HOME=.tmpgem $(BUNDLE) install
	rm -rf .tmpgem
	$(BUNDLE) install

.PHONY: clean
clean:
	rm -rf .bundle vendor

.PHONY: install
install: build
	mkdir -p $(DESTDIR)$(installdir) $(DESTDIR)$(sysconfdir)
	cp -R *.*rb *.ru Gemfile* Makefile i18n lib models public vendor \
		views .bundle $(DESTDIR)$(installdir)

.PHONY: install-build-dep
install-build-dep:
	mk-build-deps --install debian/control \
		-s sudo --tool 'apt-get --yes' --remove
	rm -f puavo-accounts-build-deps_*

.PHONY: deb
deb: install-build-dep
	dpkg-buildpackage -us -uc

.PHONY: test
test:
	$(BUNDLE) exec ruby test/all.rb

.PHONY: server
server:
	$(BUNDLE) exec puma --port 9491

.PHONY: server-dev
server-dev:
	$(BUNDLE) exec shotgun --host 0.0.0.0 --port 9491 --server puma
