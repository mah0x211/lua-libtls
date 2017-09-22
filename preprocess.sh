#!/bin/sh

set -e
set -x

VERSION="2.5.4"

rm -rf libressl*
wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${VERSION}.tar.gz
tar xvzf libressl-${VERSION}.tar.gz
mv libressl-${VERSION} libressl
cd libressl
./configure --with-openssldir=${LUA_CONFDIR} CFLAGS="-fPIC"
make
make check
