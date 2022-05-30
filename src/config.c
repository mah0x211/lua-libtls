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
 *  src/config.c
 *  lua-libtls
 *  Created by Masatoshi Teruya on 16/07/23.
 */

#include "libtls.h"

static inline int push_bool_result(lua_State *L, const char *op,
                                   ltls_config_t *cfg, int rv)
{
    if (rv != 0) {
        const char *errmsg = tls_config_error(cfg->ctx);

        lua_pushboolean(L, 0);
        if (errmsg) {
            libtls_new_error(L, op, errmsg);
        } else {
            libtls_new_error_from_errno(L, op);
        }
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int add_ticket_key_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    lua_Integer keyrev = lauxh_checkinteger(L, 2);
    size_t len         = 0;
    const char *key    = lauxh_checklstring(L, 3, &len);

    errno = 0;
    return push_bool_result(
        L, "add_ticket_key", cfg,
        tls_config_add_ticket_key(cfg->ctx, (uint32_t)keyrev,
                                  (unsigned char *)key, len));
}

static int set_session_lifetime_lua(lua_State *L)
{
    ltls_config_t *cfg   = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    lua_Integer lifetime = lauxh_checkinteger(L, 2);

    errno = 0;
    return push_bool_result(
        L, "set_session_lifetime", cfg,
        tls_config_set_session_lifetime(cfg->ctx, (int)lifetime));
}

static int set_session_id_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t len         = 0;
    const char *sid    = lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(
        L, "set_session_id", cfg,
        tls_config_set_session_id(cfg->ctx, (const unsigned char *)sid, len));
}

static int clear_keys_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_clear_keys(cfg->ctx);

    return 0;
}

static int verify_client_optional_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_verify_client_optional(cfg->ctx);

    return 0;
}

static int verify_client_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_verify_client(cfg->ctx);

    return 0;
}

static int ocsp_require_stapling_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_ocsp_require_stapling(cfg->ctx);

    return 0;
}

static int verify_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_verify(cfg->ctx);

    return 0;
}

static int insecure_noverifytime_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_insecure_noverifytime(cfg->ctx);

    return 0;
}

static int insecure_noverifyname_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_insecure_noverifyname(cfg->ctx);

    return 0;
}

static int insecure_noverifycert_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_insecure_noverifycert(cfg->ctx);

    return 0;
}

static int prefer_ciphers_server_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_prefer_ciphers_server(cfg->ctx);

    return 0;
}

static int prefer_ciphers_client_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);

    tls_config_prefer_ciphers_client(cfg->ctx);

    return 0;
}

static int set_verify_depth_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    int depth          = lauxh_checkinteger(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_verify_depth", cfg,
                            tls_config_set_verify_depth(cfg->ctx, depth));
}

static int set_session_fd_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    int fd             = lauxh_checkinteger(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_session_fd", cfg,
                            tls_config_set_session_fd(cfg->ctx, fd));
}

static int set_protocols_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    uint32_t protocols = (uint32_t)lauxh_optflags(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_protocols", cfg,
                            tls_config_set_protocols(cfg->ctx, protocols));
}

static int set_ocsp_staple_lua(lua_State *L)
{
    ltls_config_t *cfg  = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t olen         = 0;
    const uint8_t *ocsp = (const uint8_t *)lauxh_checklstring(L, 2, &olen);

    errno = 0;
    return push_bool_result(
        L, "set_ocsp_staple", cfg,
        tls_config_set_ocsp_staple_mem(cfg->ctx, ocsp, olen));
}

static int set_ocsp_staple_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *file   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ocsp_staple_file", cfg,
                            tls_config_set_ocsp_staple_file(cfg->ctx, file));
}

static int set_keypair_lua(lua_State *L)
{
    ltls_config_t *cfg  = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t clen         = 0;
    const uint8_t *cert = (const uint8_t *)lauxh_checklstring(L, 2, &clen);
    size_t klen         = 0;
    const uint8_t *key  = (const uint8_t *)lauxh_checklstring(L, 3, &klen);
    size_t olen         = 0;
    const uint8_t *ocsp = (const uint8_t *)lauxh_optlstring(L, 4, NULL, &olen);
    int rv              = 0;

    errno = 0;
    if (lua_gettop(L) < 4) {
        rv = tls_config_set_keypair_mem(cfg->ctx, cert, clen, key, klen);
    } else {
        // with ocsp
        rv = tls_config_set_keypair_ocsp_mem(cfg->ctx, cert, clen, key, klen,
                                             ocsp, olen);
    }

    return push_bool_result(L, "config.set_keypair", cfg, rv);
}

static int set_keypair_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *cert   = lauxh_checkstring(L, 2);
    const char *key    = lauxh_checkstring(L, 3);
    const char *ocsp   = lauxh_optstring(L, 4, NULL);
    int rv             = 0;

    errno = 0;
    if (lua_gettop(L) < 4) {
        rv = tls_config_set_keypair_file(cfg->ctx, cert, key);
    } else {
        // with ocsp file
        rv = tls_config_set_keypair_ocsp_file(cfg->ctx, cert, key, ocsp);
    }

    return push_bool_result(L, "config.set_keypair_file", cfg, rv);
}

static int set_key_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t len         = 0;
    const uint8_t *key = (const uint8_t *)lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(L, "config.set_key", cfg,
                            tls_config_set_key_mem(cfg->ctx, key, len));
}

static int set_key_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *file   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_key_file", cfg,
                            tls_config_set_key_file(cfg->ctx, file));
}

static int set_ecdhecurves_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *names  = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ecdhecurves", cfg,
                            tls_config_set_ecdhecurves(cfg->ctx, names));
}

static int set_ecdhecurve_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *name   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ecdhecurve", cfg,
                            tls_config_set_ecdhecurve(cfg->ctx, name));
}

static int set_dheparams_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *params = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_dheparams", cfg,
                            tls_config_set_dheparams(cfg->ctx, params));
}

static int set_crl_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t len         = 0;
    const uint8_t *crl = (const uint8_t *)lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(L, "config.set_crl", cfg,
                            tls_config_set_crl_mem(cfg->ctx, crl, len));
}

static int set_crl_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *file   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_crl_file", cfg,
                            tls_config_set_crl_file(cfg->ctx, file));
}

static int set_ciphers_lua(lua_State *L)
{
    ltls_config_t *cfg  = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *ciphers = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ciphers", cfg,
                            tls_config_set_ciphers(cfg->ctx, ciphers));
}

static int set_cert_lua(lua_State *L)
{
    ltls_config_t *cfg  = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t len          = 0;
    const uint8_t *cert = (const uint8_t *)lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(L, "config.set_cert", cfg,
                            tls_config_set_cert_mem(cfg->ctx, cert, len));
}

static int set_cert_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *file   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_cert_file", cfg,
                            tls_config_set_cert_file(cfg->ctx, file));
}

static int set_ca_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t len         = 0;
    const uint8_t *ca  = (const uint8_t *)lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(L, "config.set_ca", cfg,
                            tls_config_set_ca_mem(cfg->ctx, ca, len));
}

static int set_ca_path_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *path   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ca_path", cfg,
                            tls_config_set_ca_path(cfg->ctx, path));
}

static int set_ca_file_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *file   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_ca_file", cfg,
                            tls_config_set_ca_file(cfg->ctx, file));
}

static int set_alpn_lua(lua_State *L)
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *alpn   = lauxh_checkstring(L, 2);

    errno = 0;
    return push_bool_result(L, "config.set_alpn", cfg,
                            tls_config_set_alpn(cfg->ctx, alpn));
}

static int add_keypair_lua(lua_State *L)
{
    ltls_config_t *cfg  = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    size_t clen         = 0;
    const uint8_t *cert = (const uint8_t *)lauxh_checklstring(L, 2, &clen);
    size_t klen         = 0;
    const uint8_t *key  = (const uint8_t *)lauxh_checklstring(L, 3, &klen);
    size_t olen         = 0;
    const uint8_t *ocsp = (const uint8_t *)lauxh_optlstring(L, 4, NULL, &olen);
    int rv              = 0;

    errno = 0;
    if (lua_gettop(L) < 4) {
        rv = tls_config_add_keypair_mem(cfg->ctx, cert, clen, key, klen);
    } else {
        // with ocsp
        rv = tls_config_add_keypair_ocsp_mem(cfg->ctx, cert, clen, key, klen,
                                             ocsp, olen);
    }

    return push_bool_result(L, "config.add_keypair", cfg, rv);
}

static int add_keypair_file_lua(lua_State *L)
{
    ltls_config_t *cfg    = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    const char *cert_file = lauxh_checkstring(L, 2);
    const char *key_file  = lauxh_checkstring(L, 3);
    const char *ocsp_file = lauxh_optstring(L, 4, NULL);
    int rv                = 0;

    errno = 0;
    if (lua_gettop(L) < 4) {
        rv = tls_config_add_keypair_file(cfg->ctx, cert_file, key_file);
    } else {
        // with ocsp file
        rv = tls_config_add_keypair_ocsp_file(cfg->ctx, cert_file, key_file,
                                              ocsp_file);
    }

    return push_bool_result(L, "config.add_keypair_file", cfg, rv);
}

static int tostring_lua(lua_State *L)
{
    return libtls_tostring_mt(L, LIBTLS_CONFIG_MT);
}

static int gc_lua(lua_State *L)
{
    ltls_config_t *cfg = lua_touserdata(L, 1);

    tls_config_free(cfg->ctx);

    return 0;
}

static int new_lua(lua_State *L)
{
    ltls_config_t *cfg = lua_newuserdata(L, sizeof(ltls_config_t));

    errno    = 0;
    cfg->ctx = tls_config_new();
    if (cfg->ctx) {
        lauxh_setmetatable(L, LIBTLS_CONFIG_MT);
        return 1;
    }

    lua_pushnil(L);
    libtls_new_error_from_errno(L, "config.new");
    return 2;
}

static int load_file_lua(lua_State *L)
{
    const char *file = lauxh_checkstring(L, 1);
    char *pswd       = (char *)lauxh_optstring(L, 2, NULL);
    size_t len       = 0;
    uint8_t *content = NULL;

    errno   = 0;
    content = tls_load_file(file, &len, pswd);
    if (content) {
        lua_pushlstring(L, (const char *)content, len);
        tls_unload_file(content, len);
        return 1;
    }

    lua_pushnil(L);
    libtls_new_error_from_errno(L, "config.load_file");
    return 2;
}

static int default_ca_cert_file_lua(lua_State *L)
{
    const char *cert = tls_default_ca_cert_file();

    if (cert) {
        lua_pushstring(L, cert);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int parse_protocols_lua(lua_State *L)
{
    const char *protostr = lauxh_checkstring(L, 1);
    uint32_t protocols   = 0;

    errno = 0;
    if (tls_config_parse_protocols(&protocols, protostr) == 0) {
        lua_pushinteger(L, protocols);
        return 1;
    }

    lua_pushinteger(L, -1);
    libtls_new_error_from_errno(L, "config.parse_protocols");
    return 2;
}

LUALIB_API int luaopen_libtls_config(lua_State *L)
{
    struct luaL_Reg mmethod[] = {
        {"__gc",       gc_lua      },
        {"__tostring", tostring_lua},
        {NULL,         NULL        }
    };
    struct luaL_Reg method[] = {
        {"add_keypair_file",       add_keypair_file_lua      },
        {"add_keypair",            add_keypair_lua           },

        {"set_alpn",               set_alpn_lua              },

        {"set_ca_file",            set_ca_file_lua           },
        {"set_ca_path",            set_ca_path_lua           },
        {"set_ca",                 set_ca_lua                },

        {"set_cert_file",          set_cert_file_lua         },
        {"set_cert",               set_cert_lua              },

        {"set_ciphers",            set_ciphers_lua           },
        {"set_crl_file",           set_crl_file_lua          },
        {"set_crl",                set_crl_lua               },

        {"set_dheparams",          set_dheparams_lua         },
        {"set_ecdhecurve",         set_ecdhecurve_lua        },
        {"set_ecdhecurves",        set_ecdhecurves_lua       },

        {"set_key_file",           set_key_file_lua          },
        {"set_key",                set_key_lua               },

        {"set_keypair_file",       set_keypair_file_lua      },
        {"set_keypair",            set_keypair_lua           },

        {"set_ocsp_staple_file",   set_ocsp_staple_file_lua  },
        {"set_ocsp_staple",        set_ocsp_staple_lua       },

        {"set_protocols",          set_protocols_lua         },
        {"set_session_fd",         set_session_fd_lua        },
        {"set_verify_depth",       set_verify_depth_lua      },

        {"prefer_ciphers_client",  prefer_ciphers_client_lua },
        {"prefer_ciphers_server",  prefer_ciphers_server_lua },

        {"insecure_noverifycert",  insecure_noverifycert_lua },
        {"insecure_noverifyname",  insecure_noverifyname_lua },
        {"insecure_noverifytime",  insecure_noverifytime_lua },
        {"verify",                 verify_lua                },

        {"ocsp_require_stapling",  ocsp_require_stapling_lua },
        {"verify_client",          verify_client_lua         },
        {"verify_client_optional", verify_client_optional_lua},

        {"clear_keys",             clear_keys_lua            },

        {"set_session_id",         set_session_id_lua        },
        {"set_session_lifetime",   set_session_lifetime_lua  },
        {"add_ticket_key",         add_ticket_key_lua        },
        {NULL,                     NULL                      }
    };
    struct luaL_Reg funcs[] = {
        {"parse_protocols",      parse_protocols_lua     },
        {"default_ca_cert_file", default_ca_cert_file_lua},
        {"load_file",            load_file_lua           },
        {"new",                  new_lua                 },
        {NULL,                   NULL                    }
    };
    struct luaL_Reg *ptr = funcs;

    // register metatable
    libtls_newmetatable(L, LIBTLS_CONFIG_MT, mmethod, method);

    // create table
    lua_newtable(L);
    while (ptr->name) {
        lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        ptr++;
    }

    // add libtls.ERROR type
    libtls_error_init(L);
    lua_pop(L, 1);

    return 1;
}
