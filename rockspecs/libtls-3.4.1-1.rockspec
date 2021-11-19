rockspec_format = "3.0"
package = "libtls"
version = "3.4.1-1"
source = {
   url = "git+https://github.com/mah0x211/lua-libtls.git",
   tag = "v3.4.1"
}
description = {
   summary = "libtls bindings for lua",
   homepage = "https://github.com/mah0x211/lua-libtls",
   license = "MIT/X11",
   maintainer = "Masatoshi Fukunaga"
}
dependencies = {
   "lua >= 5.1"
}
external_dependencies = {
   LIBTLS = {
      header = "tls.h"
   }
}
build = {
   type = "builtin",
   modules = {
      libtls = {
         incdirs = {
            "deps/lauxhlib",
            "$(LIBTLS_INCDIR)"
         },
         libdirs = {
            "$(LIBTLS_LIBDIR)"
         },
         libraries = {
            "tls"
         },
         sources = {
            "src/libtls.c"
         }
      },
      ["libtls.config"] = {
         incdirs = {
            "deps/lauxhlib",
            "$(LIBTLS_INCDIR)"
         },
         libdirs = {
            "$(LIBTLS_LIBDIR)"
         },
         libraries = {
            "tls"
         },
         sources = {
            "src/config.c"
         }
      }
   }
}
