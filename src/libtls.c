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
 *  src/libtls.c
 *  lua-libtls
 *  Created by Masatoshi Teruya on 16/07/23.
 */

#include "libtls.h"

static inline void push_tls_error(lua_State *L, const char *op, ltls_t *tls)
{
    const char *errmsg = tls_error(tls->ctx);

    if (errmsg) {
        libtls_new_error(L, op, errmsg);
    } else {
        libtls_new_error_from_errno(L, op);
    }
}

static inline int push_bool_result(lua_State *L, const char *op, ltls_t *tls,
                                   int rv)
{
    if (rv != 0) {
        lua_pushboolean(L, 0);
        push_tls_error(L, op, tls);
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int peer_ocsp_url_lua(lua_State *L)
{
    ltls_t *tls   = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *s = NULL;

    errno = 0;
    s     = tls_peer_ocsp_url(tls->ctx);
    if (s) {
        lua_pushstring(L, s);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_url", tls);
    return 2;
}

static int peer_ocsp_this_update_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    time_t t    = 0;

    errno = 0;
    t     = tls_peer_ocsp_this_update(tls->ctx);
    if (t != -1) {
        lua_pushinteger(L, t);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_this_update", tls);
    return 2;
}

static int peer_ocsp_revocation_time_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    time_t t    = 0;

    errno = 0;
    t     = tls_peer_ocsp_revocation_time(tls->ctx);
    if (t != -1) {
        lua_pushinteger(L, t);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_revocation_time", tls);
    return 2;
}

static int peer_ocsp_result_lua(lua_State *L)
{
    ltls_t *tls   = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *s = NULL;

    errno = 0;
    s     = tls_peer_ocsp_result(tls->ctx);
    if (s) {
        lua_pushstring(L, s);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_result", tls);
    return 2;
}

static int peer_ocsp_response_status_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int n       = 0;

    errno = 0;
    n     = tls_peer_ocsp_response_status(tls->ctx);
    if (n != -1) {
        lua_pushinteger(L, n);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_response_status", tls);
    return 2;
}

static int peer_ocsp_next_update_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    time_t t    = 0;

    errno = 0;
    t     = tls_peer_ocsp_next_update(tls->ctx);
    if (t != -1) {
        lua_pushinteger(L, t);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_next_update", tls);
    return 2;
}

static int peer_ocsp_crl_reason_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int n       = 0;

    errno = 0;
    n     = tls_peer_ocsp_crl_reason(tls->ctx);
    if (n != -1) {
        lua_pushinteger(L, n);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_crl_reason", tls);
    return 2;
}

static int peer_ocsp_cert_status_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int n       = 0;

    errno = 0;
    n     = tls_peer_ocsp_cert_status(tls->ctx);
    if (n != -1) {
        lua_pushinteger(L, n);
        return 1;
    }
    // got error
    lua_pushnil(L);
    push_tls_error(L, "peer_ocsp_cert_status", tls);
    return 2;
}

static int ocsp_process_response_lua(lua_State *L)
{
    ltls_t *tls     = lauxh_checkudata(L, 1, LIBTLS_MT);
    size_t len      = 0;
    const char *res = lauxh_checklstring(L, 2, &len);

    errno = 0;
    return push_bool_result(
        L, "ocsp_process_response", tls,
        tls_ocsp_process_response(tls->ctx, (const unsigned char *)res, len));
}

static int conn_version_lua(lua_State *L)
{
    ltls_t *tls     = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *ver = tls_conn_version(tls->ctx);

    if (ver) {
        lua_pushstring(L, ver);
        return 1;
    }

    return 0;
}

static int conn_session_resumed_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);

    lua_pushboolean(L, tls_conn_session_resumed(tls->ctx));

    return 1;
}

static int conn_servername_lua(lua_State *L)
{
    ltls_t *tls      = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *name = tls_conn_servername(tls->ctx);

    if (name) {
        lua_pushstring(L, name);
        return 1;
    }

    return 0;
}

static int conn_cipher_strength_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);

    lua_pushinteger(L, tls_conn_cipher_strength(tls->ctx));

    return 1;
}

static int conn_cipher_lua(lua_State *L)
{
    ltls_t *tls        = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *cipher = tls_conn_cipher(tls->ctx);

    if (cipher) {
        lua_pushstring(L, cipher);
        return 1;
    }

    return 0;
}

static int conn_alpn_selected_lua(lua_State *L)
{
    ltls_t *tls      = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *alpn = tls_conn_alpn_selected(tls->ctx);

    if (alpn) {
        lua_pushstring(L, alpn);
        return 1;
    }

    return 0;
}

static int peer_cert_chain_pem_lua(lua_State *L)
{
    ltls_t *tls        = lauxh_checkudata(L, 1, LIBTLS_MT);
    size_t len         = 0;
    const uint8_t *pem = NULL;

    errno = 0;
    pem   = tls_peer_cert_chain_pem(tls->ctx, &len);
    if (!pem) {
        lua_pushnil(L);
        push_tls_error(L, "peer_cert_chain_pem", tls);
        return 2;
    }
    lua_pushlstring(L, (const char *)pem, len);
    return 1;
}

static int peer_cert_notafter_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);

    lua_pushinteger(L, tls_peer_cert_notafter(tls->ctx));

    return 1;
}

static int peer_cert_notbefore_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);

    lua_pushinteger(L, tls_peer_cert_notbefore(tls->ctx));

    return 1;
}

static int peer_cert_subject_lua(lua_State *L)
{
    ltls_t *tls     = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *sbj = tls_peer_cert_subject(tls->ctx);

    if (sbj) {
        lua_pushstring(L, sbj);
        return 1;
    }

    return 0;
}

static int peer_cert_issuer_lua(lua_State *L)
{
    ltls_t *tls     = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *iss = tls_peer_cert_issuer(tls->ctx);

    if (iss) {
        lua_pushstring(L, iss);
        return 1;
    }

    return 0;
}

static int peer_cert_hash_lua(lua_State *L)
{
    ltls_t *tls      = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *hash = tls_peer_cert_hash(tls->ctx);

    if (hash) {
        lua_pushstring(L, hash);
        return 1;
    }

    return 0;
}

static int peer_cert_contains_name_lua(lua_State *L)
{
    ltls_t *tls      = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *name = lauxh_checkstring(L, 2);

    lua_pushboolean(L, tls_peer_cert_contains_name(tls->ctx, name));

    return 1;
}

static int peer_cert_provided_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);

    lua_pushboolean(L, tls_peer_cert_provided(tls->ctx));

    return 1;
}

static int close_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int rv      = tls_close(tls->ctx);

    switch (rv) {
    case 0:
        lua_pushboolean(L, 1);
        return 1;

    case TLS_WANT_POLLIN:
    case TLS_WANT_POLLOUT:
        lua_pushboolean(L, 0);
        lua_pushnil(L);
        lua_pushinteger(L, rv);
        return 3;

    default:
        lua_pushboolean(L, 0);
        push_tls_error(L, "close", tls);
        return 2;
    }
}

static int write_lua(lua_State *L)
{
    ltls_t *tls     = lauxh_checkudata(L, 1, LIBTLS_MT);
    size_t len      = 0;
    const char *buf = lauxh_checklstring(L, 2, &len);
    ssize_t rv      = tls_write(tls->ctx, buf, len);

    switch (rv) {
    // closed by peer
    case 0:
        return 0;

    // got error
    case -1:
        lua_pushnil(L);
        push_tls_error(L, "write", tls);
        return 2;

    // again
    case TLS_WANT_POLLIN:
    case TLS_WANT_POLLOUT:
        lua_pushinteger(L, 0);
        lua_pushnil(L);
        lua_pushboolean(L, 1);
        lua_pushinteger(L, rv);
        return 4;

    default:
        lua_pushinteger(L, rv);
        if (len - (size_t)rv) {
            lua_pushnil(L);
            lua_pushboolean(L, 1);
            lua_pushinteger(L, TLS_WANT_POLLOUT);
            return 4;
        }
        return 1;
    }
}

static int read_lua(lua_State *L)
{
    ltls_t *tls        = lauxh_checkudata(L, 1, LIBTLS_MT);
    lua_Integer bufsiz = lauxh_optinteger(L, 2, BUFSIZ);
    void *buf          = NULL;
    ssize_t rv         = 0;

    // allocate buffer from lua vm
    if (bufsiz < 0) {
        bufsiz = BUFSIZ;
    }

    buf = lua_newuserdata(L, bufsiz);
    rv  = tls_read(tls->ctx, buf, bufsiz);
    switch (rv) {
    // closed by peer
    case 0:
        return 0;

    // got error
    case -1:
        lua_pushnil(L);
        push_tls_error(L, "read", tls);
        return 2;

    // again
    case TLS_WANT_POLLIN:
    case TLS_WANT_POLLOUT:
        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushboolean(L, 1);
        lua_pushinteger(L, rv);
        return 4;

    default:
        lua_pushlstring(L, buf, rv);
        return 1;
    }
}

static int handshake_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int rv      = tls_handshake(tls->ctx);

    switch (rv) {
    case 0:
        lua_pushboolean(L, 1);
        return 1;

    case -1:
        lua_pushboolean(L, 0);
        push_tls_error(L, "handshake", tls);
        return 2;

    default:
        lua_pushboolean(L, 0);
        lua_pushnil(L);
        lua_pushinteger(L, rv);
        return 3;
    }
}

static int connect_socket_lua(lua_State *L)
{
    ltls_t *tls            = lauxh_checkudata(L, 1, LIBTLS_MT);
    int sock               = lauxh_checkinteger(L, 2);
    const char *servername = lauxh_optstring(L, 3, NULL);

    errno = 0;
    return push_bool_result(L, "connect_socket", tls,
                            tls_connect_socket(tls->ctx, sock, servername));
}

static int connect_servername_lua(lua_State *L)
{
    ltls_t *tls            = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *host       = lauxh_checkstring(L, 2);
    const char *port       = lauxh_optstring(L, 3, NULL);
    const char *servername = lauxh_optstring(L, 4, NULL);

    errno = 0;
    return push_bool_result(
        L, "connect_servername", tls,
        tls_connect_servername(tls->ctx, host, port, servername));
}

static int connect_fds_lua(lua_State *L)
{
    ltls_t *tls            = lauxh_checkudata(L, 1, LIBTLS_MT);
    int fdr                = lauxh_checkinteger(L, 2);
    int fdw                = lauxh_checkinteger(L, 3);
    const char *servername = lauxh_optstring(L, 4, NULL);

    errno = 0;
    return push_bool_result(L, "connect_fds", tls,
                            tls_connect_fds(tls->ctx, fdr, fdw, servername));
}

static int connect_lua(lua_State *L)
{
    ltls_t *tls      = lauxh_checkudata(L, 1, LIBTLS_MT);
    const char *host = lauxh_checkstring(L, 2);
    const char *port = lauxh_optstring(L, 3, NULL);

    errno = 0;
    return push_bool_result(L, "connect", tls,
                            tls_connect(tls->ctx, host, port));
}

static int accept_socket_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int sock    = lauxh_checkinteger(L, 2);
    ltls_t *c   = lua_newuserdata(L, sizeof(ltls_t));

    if (tls_accept_socket(tls->ctx, &c->ctx, sock)) {
        lua_pushnil(L);
        push_tls_error(L, "accept_socket", tls);
        return 2;
    }
    lauxh_setmetatable(L, LIBTLS_MT);
    return 1;
}

static int accept_fds_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    int fdr     = lauxh_checkinteger(L, 2);
    int fdw     = lauxh_checkinteger(L, 3);
    ltls_t *c   = lua_newuserdata(L, sizeof(ltls_t));

    if (tls_accept_fds(tls->ctx, &c->ctx, fdr, fdw)) {
        lua_pushnil(L);
        push_tls_error(L, "accept_fds", tls);
        return 2;
    }
    lauxh_setmetatable(L, LIBTLS_MT);
    return 1;
}

static int reset_lua(lua_State *L)
{
    ltls_t *tls = lauxh_checkudata(L, 1, LIBTLS_MT);
    tls_reset(tls->ctx);
    return 0;
}

static int tostring_lua(lua_State *L)
{
    return libtls_tostring_mt(L, LIBTLS_MT);
}

static int gc_lua(lua_State *L)
{
    ltls_t *tls = lua_touserdata(L, 1);
    tls_free(tls->ctx);
    return 0;
}

static int new_lua(lua_State *L, const char *op, struct tls *(*fn)(void))
{
    ltls_config_t *cfg = lauxh_checkudata(L, 1, LIBTLS_CONFIG_MT);
    ltls_t *tls        = lua_newuserdata(L, sizeof(ltls_t));

    errno    = 0;
    tls->ctx = fn();
    if (!tls->ctx) {
        lua_pushnil(L);
        libtls_new_error_from_errno(L, op);
        return 2;
    } else if (tls_configure(tls->ctx, cfg->ctx)) {
        lua_pushnil(L);
        push_tls_error(L, op, tls);
        tls_free(tls->ctx);
        return 2;
    }
    lauxh_setmetatable(L, LIBTLS_MT);
    return 1;
}

static int server_lua(lua_State *L)
{
    return new_lua(L, "server", tls_server);
}

static int client_lua(lua_State *L)
{
    return new_lua(L, "client", tls_client);
}

LUALIB_API int luaopen_libtls(lua_State *L)
{
    struct luaL_Reg mmethod[] = {
        {"__gc",       gc_lua      },
        {"__tostring", tostring_lua},
        {NULL,         NULL        }
    };
    struct luaL_Reg method[] = {
        {"reset",                     reset_lua                    },

        {"accept_fds",                accept_fds_lua               },
        {"accept_socket",             accept_socket_lua            },
 // TODO: check the purpose and usage
  // {"accept_cbs",                accept_cbs_lua               },

        {"connect",                   connect_lua                  },
        {"connect_fds",               connect_fds_lua              },
        {"connect_servername",        connect_servername_lua       },
        {"connect_socket",            connect_socket_lua           },
 // TODO: check the purpose and usage
  // {"connect_cbs",               connect_cbs_lua              },

        {"handshake",                 handshake_lua                },

        {"read",                      read_lua                     },
        {"write",                     write_lua                    },
        {"close",                     close_lua                    },

        {"peer_cert_provided",        peer_cert_provided_lua       },
        {"peer_cert_contains_name",   peer_cert_contains_name_lua  },

        {"peer_cert_hash",            peer_cert_hash_lua           },
        {"peer_cert_issuer",          peer_cert_issuer_lua         },
        {"peer_cert_subject",         peer_cert_subject_lua        },
        {"peer_cert_notbefore",       peer_cert_notbefore_lua      },
        {"peer_cert_notafter",        peer_cert_notafter_lua       },
        {"peer_cert_chain_pem",       peer_cert_chain_pem_lua      },

        {"conn_alpn_selected",        conn_alpn_selected_lua       },
        {"conn_cipher",               conn_cipher_lua              },
        {"conn_cipher_strength",      conn_cipher_strength_lua     },
        {"conn_servername",           conn_servername_lua          },
        {"conn_session_resumed",      conn_session_resumed_lua     },
        {"conn_version",              conn_version_lua             },

        {"ocsp_process_response",     ocsp_process_response_lua    },
        {"peer_ocsp_cert_status",     peer_ocsp_cert_status_lua    },
        {"peer_ocsp_crl_reason",      peer_ocsp_crl_reason_lua     },
        {"peer_ocsp_next_update",     peer_ocsp_next_update_lua    },
        {"peer_ocsp_response_status", peer_ocsp_response_status_lua},
        {"peer_ocsp_result",          peer_ocsp_result_lua         },
        {"peer_ocsp_revocation_time", peer_ocsp_revocation_time_lua},
        {"peer_ocsp_this_update",     peer_ocsp_this_update_lua    },
        {"peer_ocsp_url",             peer_ocsp_url_lua            },
        {NULL,                        NULL                         }
    };
    struct luaL_Reg funcs[] = {
        {"client", client_lua},
        {"server", server_lua},
        {NULL,     NULL      }
    };
    struct luaL_Reg *ptr = funcs;

    // initialize global data
    if (tls_init()) {
        lua_pushstring(L, strerror(errno));
        return lua_error(L);
    }

    // register metatable
    libtls_newmetatable(L, LIBTLS_MT, mmethod, method);

    // create table
    lua_newtable(L);
    while (ptr->name) {
        lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        ptr++;
    }

    // add TLS_WANT_* constants
    lauxh_pushint2tbl(L, "WANT_POLLIN", TLS_WANT_POLLIN);
    lauxh_pushint2tbl(L, "WANT_POLLOUT", TLS_WANT_POLLOUT);

    // add TLS_PROTOCOLS_* constants
    lauxh_pushint2tbl(L, "TLS_v10", TLS_PROTOCOL_TLSv1_0);
    lauxh_pushint2tbl(L, "TLS_v11", TLS_PROTOCOL_TLSv1_1);
    lauxh_pushint2tbl(L, "TLS_v12", TLS_PROTOCOL_TLSv1_2);
    lauxh_pushint2tbl(L, "TLS_v13", TLS_PROTOCOL_TLSv1_3);
    lauxh_pushint2tbl(L, "TLS_v1x", TLS_PROTOCOL_TLSv1);
    lauxh_pushint2tbl(L, "TLS_DEFAULT", TLS_PROTOCOLS_DEFAULT);

    // RFC 6960 Section 2.2
    // add TLS_OCSP_CERT_* constants
    lauxh_pushint2tbl(L, "OCSP_CERT_GOOD", TLS_OCSP_CERT_GOOD);
    lauxh_pushint2tbl(L, "OCSP_CERT_REVOKED", TLS_OCSP_CERT_REVOKED);
    lauxh_pushint2tbl(L, "OCSP_CERT_UNKNOWN", TLS_OCSP_CERT_UNKNOWN);

    // RFC 6960 Section 2.3
    // add TLS_OCSP_RESPONSE_* constants
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_SUCCESSFUL",
                      TLS_OCSP_RESPONSE_SUCCESSFUL);
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_MALFORMED",
                      TLS_OCSP_RESPONSE_MALFORMED);
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_INTERNALERROR",
                      TLS_OCSP_RESPONSE_INTERNALERROR);
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_TRYLATER", TLS_OCSP_RESPONSE_TRYLATER);
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_SIGREQUIRED",
                      TLS_OCSP_RESPONSE_SIGREQUIRED);
    lauxh_pushint2tbl(L, "OCSP_RESPONSE_UNAUTHORIZED",
                      TLS_OCSP_RESPONSE_UNAUTHORIZED);

    // RFC 5280 Section 5.3.1
    // add TLS_CRL_REASON_* constants
    lauxh_pushint2tbl(L, "CRL_REASON_UNSPECIFIED", TLS_CRL_REASON_UNSPECIFIED);
    lauxh_pushint2tbl(L, "CRL_REASON_KEY_COMPROMISE",
                      TLS_CRL_REASON_KEY_COMPROMISE);
    lauxh_pushint2tbl(L, "CRL_REASON_CA_COMPROMISE",
                      TLS_CRL_REASON_CA_COMPROMISE);
    lauxh_pushint2tbl(L, "CRL_REASON_AFFILIATION_CHANGED",
                      TLS_CRL_REASON_AFFILIATION_CHANGED);
    lauxh_pushint2tbl(L, "CRL_REASON_SUPERSEDED", TLS_CRL_REASON_SUPERSEDED);
    lauxh_pushint2tbl(L, "CRL_REASON_CESSATION_OF_OPERATION",
                      TLS_CRL_REASON_CESSATION_OF_OPERATION);
    lauxh_pushint2tbl(L, "CRL_REASON_CERTIFICATE_HOLD",
                      TLS_CRL_REASON_CERTIFICATE_HOLD);
    lauxh_pushint2tbl(L, "CRL_REASON_REMOVE_FROM_CRL",
                      TLS_CRL_REASON_REMOVE_FROM_CRL);
    lauxh_pushint2tbl(L, "CRL_REASON_PRIVILEGE_WITHDRAWN",
                      TLS_CRL_REASON_PRIVILEGE_WITHDRAWN);
    lauxh_pushint2tbl(L, "CRL_REASON_AA_COMPROMISE",
                      TLS_CRL_REASON_AA_COMPROMISE);

    lauxh_pushint2tbl(L, "TLS_API", TLS_API);
    lauxh_pushint2tbl(L, "MAX_SESSION_ID_LENGTH", TLS_MAX_SESSION_ID_LENGTH);
    lauxh_pushint2tbl(L, "TICKET_KEY_SIZE", TLS_TICKET_KEY_SIZE);

    // add libtls.ERROR type
    libtls_error_init(L);
    lua_setfield(L, -2, "ERROR");

    return 1;
}
