prefix ?= /var/app
sysconfdir = /etc
installdir = $(prefix)/puavo-accounts

RUBY = /usr/bin/ruby
BUNDLE = $(RUBY) /usr/bin/bundle

.PHONY: build
build:
	$(BUNDLE) install --deployment

.PHONY: update-gemfile-lock
update-gemfile-lock: clean
	rm -f Gemfile.lock
	GEM_HOME=.tmpgem $(BUNDLE) install
	rm -rf .tmpgem
	$(BUNDLE) install --deployment

.PHONY: clean
clean:
	rm -rf .bundle vendor

.PHONY: clean-for-install
clean-for-install:
	$(BUNDLE) install --deployment --without test
	$(BUNDLE) clean

.PHONY: install
install: clean-for-install
	mkdir -p $(DESTDIR)$(installdir)
	mkdir -p $(DESTDIR)$(sysconfdir)
	cp -r *.*rb *.ru Gemfile* Makefile i18n lib models  public vendor views .bundle $(DESTDIR)$(installdir)

.PHONY: install-build-dep
install-build-dep:
	mk-build-deps --install debian/control \
		--tool "apt-get --yes --force-yes" --remove

.PHONY: deb
deb: install-build-dep
	dpkg-buildpackage -us -uc

.PHONY: server
server:
	$(BUNDLE) exec puma --port 9491

.PHONY: server-dev
server-dev:
	$(BUNDLE) exec shotgun --host 0.0.0.0 --port 9491 --server puma
