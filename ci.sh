#!/bin/sh

set -x

sudo apt-get update

# FIXME: skip error when run apt-get update. This should be fix when mirror is reliable
set -eu

# Install build dependencies
sudo make install-build-dep

# Build debian package
make deb

mkdir -p $HOME/results
cp ../puavo-accounts_* $HOME/results
