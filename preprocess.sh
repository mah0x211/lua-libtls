#!/bin/sh

set -e
set -x

cd deps/libressl/
./autogen.sh
./configure --with-openssldir=${LUA_CONFDIR}
make
make check
