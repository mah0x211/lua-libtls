#!/bin/sh

DIRNAME="libressl-${VERSION}"
ARCHIVE="${DIRNAME}.tar.gz"
FILE_CFLAGS="libtls-cflags"
FILE_LDFLAGS="libtls-ldflags"
FILE_LIBS="libtls-libs"

#
# checking environment variables
#
if [ -z "$VERSION" ]; then
    echo 'ERROR: the VERSION environment is not defind'
    exit -1
elif [ -z "$CONFDIR" ]; then
    echo 'ERROR: the CONFDIR environment is not defind'
    exit -1
fi


#
# checking system installed version
#
pkg-config --atleast-version $VERSION libtls
if [ $? = 0 ]; then
    echo "use system installed libtls-$(pkg-config --modversion libtls)"
    echo "$(pkg-config --cflags libtls)" > $FILE_CFLAGS
    echo "$(pkg-config --libs libtls)" > $FILE_LDFLAGS
    echo "" > $FILE_LIBS
    exit 0
fi

set -x
set -e

echo "-I../libressl/include" > $FILE_CFLAGS
echo "" > $FILE_LDFLAGS
echo "../libressl/tls/.libs/libtls.a ../libressl/ssl/.libs/libssl.a ../libressl/crypto/.libs/libcrypto.a" > $FILE_LIBS

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
./configure --with-openssldir=${CONFDIR} CFLAGS="-fPIC"
make
make check
install -d $CONFDIR
install ./apps/openssl/cert.pem $CONFDIR
install ./apps/openssl/openssl.cnf $CONFDIR
install ./apps/openssl/x509v3.cnf $CONFDIR

