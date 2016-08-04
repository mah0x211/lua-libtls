package = "libtls"
version = "2.4.2-1"
source = {
    url = "gitrec://github.com/mah0x211/lua-libtls.git",
    tag = "v2.4.2"
}
description = {
    summary = "libtls bindings for lua",
    homepage = "https://github.com/mah0x211/lua-libtls",
    license = "MIT/X11",
    maintainer = "Masatoshi Teruya"
}
dependencies = {
    "lua >= 5.1",
    "luarocks-fetch-gitrec >= 0.2"
}
build = {
    type = "command",
    build_command = [[
        LUA_CONFDIR="$(CONFDIR)" sh preprocess.sh && autoreconf -ivf && CFLAGS="$(CFLAGS)" CPPFLAGS="-I$(LUA_INCDIR)" LIBFLAG="$(LIBFLAG)" OBJ_EXTENSION="$(OBJ_EXTENSION)" LIB_EXTENSION="$(LIB_EXTENSION)" LIBDIR="$(LIBDIR)" CONFDIR="$(CONFDIR)" ./configure && make clean && make
    ]],
    install_command = [[
        make install
    ]]
}

