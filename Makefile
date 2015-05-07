prefix = /usr/local
sysconfdir = /etc
installdir = /var/app/puavo-accounts

build:
	bundle install --deployment

update-gemfile-lock: clean
	rm -f Gemfile.lock
	GEM_HOME=.tmpgem bundle install
	rm -rf .tmpgem
	bundle install --deployment

clean:
	rm -rf .bundle vendor
