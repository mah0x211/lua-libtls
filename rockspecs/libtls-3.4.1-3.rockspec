package = "libtls"
version = "3.4.1-3"
source = {
    url = "git+https://github.com/mah0x211/lua-libtls.git",
    tag = "v3.4.1",
}
description = {
    summary = "libtls bindings for lua",
    homepage = "https://github.com/mah0x211/lua-libtls",
    license = "MIT/X11",
    maintainer = "Masatoshi Fukunaga",
}
dependencies = {
    "lua >= 5.1",
    "error >= 0.8.0",
    "lauxhlib >= 0.3.1",
}
external_dependencies = {
    LIBTLS = {
        header = "tls.h",
        library = "tls",
    },
}
build = {
    type = "make",
    build_variables = {
        SRCDIR = "src",
        CFLAGS = "$(CFLAGS)",
        WARNINGS = "-Wall -Wno-trigraphs -Wmissing-field-initializers -Wreturn-type -Wmissing-braces -Wparentheses -Wno-switch -Wunused-function -Wunused-label -Wunused-parameter -Wunused-variable -Wunused-value -Wuninitialized -Wunknown-pragmas -Wshadow -Wsign-compare",
        CPPFLAGS = "-I$(LUA_INCDIR) -I$(LIBTLS_INCDIR)",
        LDFLAGS = "$(LIBFLAG) -L$(LIBTLS_LIBDIR) -ltls",
        LIB_EXTENSION = "$(LIB_EXTENSION)",
        LIBTLS_COVERAGE = "$(LIBTLS_COVERAGE)",
    },
    install_variables = {
        SRCDIR = "src",
        INST_LIBDIR = "$(LIBDIR)",
        LIB_EXTENSION = "$(LIB_EXTENSION)",
    },
}
