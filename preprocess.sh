#!/bin/sh

set -e
set -x

VERSION="2.7.3"
DIRNAME="libressl-${VERSION}"
ARCHIVE="${DIRNAME}.tar.gz"


#
# download archive file
#
if [ ! -f $ARCHIVE ]; then
    rm -rf libressl*
    wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/$ARCHIVE
fi

#
# extract archive file
#
if [ ! -d "libressl" ]; then
    tar xvzf $ARCHIVE
    mv $DIRNAME libressl
fi

cd libressl
./configure --with-openssldir=${LUA_CONFDIR} CFLAGS="-fPIC"
make
make check
