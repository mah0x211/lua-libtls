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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// lua
#include "tls.h"
#include <lua_error.h>

static inline void libtls_error_init(lua_State *L)
{
    int top = lua_gettop(L);

    if (!le_registry_get(L, "libtls.ERROR")) {
        // register libtls.ERROR type
        lua_pushliteral(L, "libtls.ERROR");
        lua_pushinteger(L, -1);
        lua_pushliteral(L, "Operation failure");
        le_new_type(L, top + 1);
    }
}

static inline void libtls_new_error(lua_State *L, const char *op,
                                    const char *msg)
{
    int top = lua_gettop(L);

    le_registry_get(L, "libtls.ERROR");
    if (msg || op) {
        if (msg) {
            lua_pushstring(L, msg);
        } else {
            lua_pushnil(L);
        }
        if (op) {
            lua_pushstring(L, op);
        } else {
            lua_pushnil(L);
        }
        le_new_message(L, top + 2);
    }
    le_new_typed_error(L, top + 1);
}

static inline void libtls_new_error_from_errno(lua_State *L, const char *op)
{
    if (errno) {
        libtls_new_error(L, op, strerror(errno));
    } else {
        libtls_new_error(L, op, NULL);
    }
}

static inline int libtls_tostring_mt(lua_State *L, const char *tname)
{
    lua_pushfstring(L, "%s: %p", tname, lua_touserdata(L, 1));
    return 1;
}

// helper functions

static inline void libtls_newmetatable(lua_State *L, const char *tname,
                                       struct luaL_Reg mm[], luaL_Reg m[])
{
    // register metatable
    if (luaL_newmetatable(L, tname)) {
        struct luaL_Reg *ptr = mm;
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
