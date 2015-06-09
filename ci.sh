#!/bin/sh

set -x
set -eu

sudo apt-get update

# Install build dependencies
sudo make install-build-dep

# Build debian package
make deb

mkdir -p $HOME/results
cp ../puavo-accounts_* $HOME/results
