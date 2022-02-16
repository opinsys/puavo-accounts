prefix ?= /var/app
sysconfdir = /etc
installdir = $(prefix)/puavo-accounts

RUBY = /usr/bin/ruby
BUNDLE = $(RUBY) /usr/bin/bundle

build:
	$(BUNDLE) install --deployment

update-gemfile-lock: clean
	rm -f Gemfile.lock
	GEM_HOME=.tmpgem $(BUNDLE) install
	rm -rf .tmpgem
	$(BUNDLE) install --deployment

clean:
	rm -rf .bundle vendor

clean-for-install:
		$(BUNDLE) install --deployment --without test
		$(BUNDLE) clean

install: clean-for-install
	mkdir -p $(DESTDIR)$(installdir)
	mkdir -p $(DESTDIR)$(sysconfdir)
	cp -r *.*rb *.ru Gemfile* Makefile i18n lib models  public vendor views .bundle $(DESTDIR)$(installdir)


install-build-dep:
	mk-build-deps --install debian/control \
		--tool "apt-get --yes --force-yes" --remove

deb:
	dpkg-buildpackage -us -uc

server:
	$(BUNDLE) exec puma --port 9491

server-dev:
	$(BUNDLE) exec shotgun --host 0.0.0.0 --port 9491 --server puma
