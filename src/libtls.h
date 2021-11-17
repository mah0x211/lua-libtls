/**
 *  Copyright (C) 2016 Masatoshi Teruya
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 *  src/libtls.h
 *  lua-libtls
 *  Created by Masatoshi Teruya on 16/07/23.
 */

#ifndef libtls_lua_h
#define libtls_lua_h

#include "config.h"
#include "lauxhlib.h"
#include "lua_iovec.h"
#include "tls.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TOSTRING_MT(L, tname)                                                  \
 (                                                                             \
     {                                                                         \
lua_pushfstring(L, tname ": %p", lua_touserdata(L, 1));                        \
1;                                                                             \
     })

// helper functions

static inline void libtls_newmetatable(lua_State *L, const char *tname,
                                       struct luaL_Reg mm[], luaL_Reg m[])
{
    struct luaL_Reg *ptr = mm;

    // register metatable
    luaL_newmetatable(L, tname);
    while (ptr->name) {
        lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        ptr++;
    }
    // push methods into __index table
    lua_pushstring(L, "__index");
    lua_newtable(L);
    ptr = m;
    while (ptr->name) {
        lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        ptr++;
    }
    lua_rawset(L, -3);
    lua_pop(L, 1);
}

// define module names
#define LIBTLS_MT        "libtls"
#define LIBTLS_CONFIG_MT "libtls.config"

// define data wrapper

typedef struct {
    struct tls_config *ctx;
} ltls_config_t;

typedef struct {
    struct tls *ctx;
} ltls_t;

// define prototypes
LUALIB_API int luaopen_libtls(lua_State *L);
LUALIB_API int luaopen_libtls_config(lua_State *L);

#endif
