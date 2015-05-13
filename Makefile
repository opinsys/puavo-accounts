prefix = /usr/local
sysconfdir = /etc
installdir = /var/app/puavo-accounts
$(INSTALL_PROGRAM)

BUNDLE = /usr/bin/bundle
RUBY = /usr/bin/ruby2.0

build:
	$(RUBY) $(BUNDLE) install --deployment

update-gemfile-lock: clean
	rm -f Gemfile.lock
	GEM_HOME=.tmpgem $(RUBY) $(BUNDLE) install
	rm -rf .tmpgem
	$(RUBY) $(BUNDLE) install --deployment

clean:
	rm -rf .bundle vendor

install-build-dep:
	mk-build-deps --install debian.default/control \
		--tool "apt-get --yes --force-yes" --remove

server:
	$(RUBY) $(BUNDLE) exec puma

serve-dev:
	$(RUBY) $(BUNDLE) exec shotgun --host 0.0.0.0 --port 9494 --server puma
