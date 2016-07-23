#!/bin/sh

set -e
set -x

cd deps/libressl/
./autogen.sh
./configure
make
make check
