/*
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


static inline int tls_error_lua( lua_State *L, ltls_t *tls )
{
    const char *errstr = tls_error( tls->ctx );

    lua_pushboolean( L, 0 );
    if( errstr ){
        lua_pushstring( L, errstr );
    }
    else {
        lua_pushstring( L, strerror( errno ) );
    }
    return 2;
}


static int ocsp_process_response_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    size_t len = 0;
    const char *res = lauxh_checklstring( L, 2, &len );

    if( tls_ocsp_process_response( tls->ctx, (const unsigned char*)res, len ) ){
        return tls_error_lua( L, tls );
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int conn_version_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *ver = tls_conn_version( tls->ctx );

    if( ver ){
        lua_pushstring( L, ver );
        return 1;
    }

    return 0;
}


static int conn_servername_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *name = tls_conn_servername( tls->ctx );

    if( name ){
        lua_pushstring( L, name );
        return 1;
    }

    return 0;
}


static int conn_cipher_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *cipher = tls_conn_cipher( tls->ctx );

    if( cipher ){
        lua_pushstring( L, cipher );
        return 1;
    }

    return 0;
}


static int conn_alpn_selected_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *alpn = tls_conn_alpn_selected( tls->ctx );

    if( alpn ){
        lua_pushstring( L, alpn );
        return 1;
    }

    return 0;
}


static int peer_cert_notafter_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );

    lua_pushnumber( L, tls_peer_cert_notafter( tls->ctx ) );

    return 1;
}


static int peer_cert_notbefore_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );

    lua_pushnumber( L, tls_peer_cert_notbefore( tls->ctx ) );

    return 1;
}


static int peer_cert_subject_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *sbj = tls_peer_cert_subject( tls->ctx );

    if( sbj ){
        lua_pushstring( L, sbj );
        return 1;
    }

    return 0;
}


static int peer_cert_issuer_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *iss = tls_peer_cert_issuer( tls->ctx );

    if( iss ){
        lua_pushstring( L, iss );
        return 1;
    }

    return 0;
}


static int peer_cert_hash_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *hash = tls_peer_cert_hash( tls->ctx );

    if( hash ){
        lua_pushstring( L, hash );
        return 1;
    }

    return 0;
}


static int peer_cert_contains_name_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *name = lauxh_checkstring( L, 2 );

    lua_pushboolean( L, tls_peer_cert_contains_name( tls->ctx, name ) );

    return 1;
}


static int peer_cert_provided_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );

    lua_pushboolean( L, tls_peer_cert_provided( tls->ctx ) );

    return 1;
}


static int close_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );

    if( tls_close( tls->ctx ) ){
        return tls_error_lua( L, tls );
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int write_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    size_t len = 0;
    const char *buf = lauxh_checklstring( L, 2, &len );
    ssize_t rv = tls_write( tls->ctx, buf, len );

    switch( rv ){
        // closed by peer
        case 0:
            return 0;

        // got error
        case -1:
            return tls_error_lua( L, tls );

        // again
        case TLS_WANT_POLLIN:
        case TLS_WANT_POLLOUT:
            lua_pushinteger( L, 0 );
            lua_pushnil( L );
            lua_pushboolean( L, 1 );
            return 3;

        default:
            lua_pushinteger( L, rv );
            lua_pushnil( L );
            lua_pushboolean( L, len - (size_t)rv );
            return 3;
    }
}


static int read_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    size_t len = lauxh_optinteger( L, 2, BUFSIZ );
    void *buf = malloc( len );
    ssize_t rv = 0;

    if( !buf ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    rv = tls_read( tls->ctx, buf, len );
    switch( rv ){
        // closed by peer
        case 0:
        break;

        // got error
        case -1:
            rv = tls_error_lua( L, tls );
        break;

        // again
        case TLS_WANT_POLLIN:
        case TLS_WANT_POLLOUT:
            lua_pushnil( L );
            lua_pushnil( L );
            lua_pushboolean( L, 1 );
            rv = 3;
        break;

        default:
            lua_pushlstring( L, buf, rv );
            rv = 1;
    }

    free( buf );

    return rv;
}


static int handshake_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );

    if( tls_handshake( tls->ctx ) ){
        return tls_error_lua( L, tls );
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int connect_socket_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    int sock = lauxh_checkinteger( L, 2 );
    const char *servername = lauxh_optstring( L, 3, NULL );

    if( tls_connect_socket( tls->ctx, sock, servername ) ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int connect_servername_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *host = lauxh_checkstring( L, 2 );
    const char *port = lauxh_optstring( L, 3, NULL );
    const char *servername = lauxh_optstring( L, 4, NULL );

    if( tls_connect_servername( tls->ctx, host, port, servername ) ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int connect_fds_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    int fdr = lauxh_checkinteger( L, 2 );
    int fdw = lauxh_checkinteger( L, 3 );
    const char *servername = lauxh_optstring( L, 4, NULL );

    if( tls_connect_fds( tls->ctx, fdr, fdw, servername ) ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int connect_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    const char *host = lauxh_checkstring( L, 2 );
    const char *port = lauxh_optstring( L, 3, NULL );

    if( tls_connect( tls->ctx, host, port ) ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lua_pushboolean( L, 1 );

    return 1;
}


static int accept_socket_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    int sock = lauxh_checkinteger( L, 2 );
    ltls_t *c = lua_newuserdata( L, sizeof( ltls_t ) );

    if( !c ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }
    else if( tls_accept_socket( tls->ctx, &c->ctx, sock ) ){
        lua_pushnil( L );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lauxh_setmetatable( L, LIBTLS_MT );

    return 1;
}


static int accept_fds_lua( lua_State *L )
{
    ltls_t *tls = lauxh_checkudata( L, 1, LIBTLS_MT );
    int fdr = lauxh_checkinteger( L, 2 );
    int fdw = lauxh_checkinteger( L, 3 );
    ltls_t *c = lua_newuserdata( L, sizeof( ltls_t ) );

    if( !c ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }
    else if( tls_accept_fds( tls->ctx, &c->ctx, fdr, fdw ) ){
        lua_pushnil( L );
        lua_pushstring( L, tls_error( tls->ctx ) );
        return 2;
    }

    lauxh_setmetatable( L, LIBTLS_MT );

    return 1;
}


static int tostring_lua( lua_State *L )
{
    return TOSTRING_MT( L, LIBTLS_MT );
}


static int gc_lua( lua_State *L )
{
    ltls_t *tls = lua_touserdata( L, 1 );

    tls_free( tls->ctx );

    return 0;
}


static int new_lua( lua_State *L, struct tls *(*fn)( void ) )
{
    ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
    ltls_t *tls = lua_newuserdata( L, sizeof( ltls_t ) );

    if( !tls || !( tls->ctx = fn() ) || tls_configure( tls->ctx, cfg->ctx ) )
    {
        if( tls && tls->ctx ){
            tls_free( tls->ctx );
        }
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    lauxh_setmetatable( L, LIBTLS_MT );

    return 1;
}


static int server_lua( lua_State *L )
{
    return new_lua( L, tls_server );
}


static int client_lua( lua_State *L )
{
    return new_lua( L, tls_client );
}


LUALIB_API int luaopen_libtls( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "accept_fds", accept_fds_lua },
        { "accept_socket", accept_socket_lua },
        { "connect", connect_lua },
        { "connect_fds", connect_fds_lua },
        { "connect_servername", connect_servername_lua },
        { "connect_socket", connect_socket_lua },
        { "handshake", handshake_lua },
        { "read", read_lua },
        { "write", write_lua },
        { "close", close_lua },
        { "peer_cert_provided", peer_cert_provided_lua },
        { "peer_cert_contains_name", peer_cert_contains_name_lua },
        { "peer_cert_hash", peer_cert_hash_lua },
        { "peer_cert_issuer", peer_cert_issuer_lua },
        { "peer_cert_subject", peer_cert_subject_lua },
        { "peer_cert_notbefore", peer_cert_notbefore_lua },
        { "peer_cert_notafter", peer_cert_notafter_lua },
        { "conn_alpn_selected", conn_alpn_selected_lua },
        { "conn_cipher", conn_cipher_lua },
        { "conn_servername", conn_servername_lua },
        { "conn_version", conn_version_lua },
        { "ocsp_process_response", ocsp_process_response_lua },
        { NULL, NULL }
    };
    struct luaL_Reg funcs[] = {
        { "client", client_lua },
        { "server", server_lua },
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = funcs;

    // initialize global data
    if( tls_init() ){
        lua_pushstring( L, strerror( errno ) );
        return lua_error( L );
    }

    // register metatable
    libtls_newmetatable( L, LIBTLS_MT, mmethod, method );

    // create table
    lua_newtable( L );
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }

    // add TLS_PROTOCOLS_* constants
    lauxh_pushint2tbl( L, "TLS_v10", TLS_PROTOCOL_TLSv1_0 );
    lauxh_pushint2tbl( L, "TLS_v11", TLS_PROTOCOL_TLSv1_1 );
    lauxh_pushint2tbl( L, "TLS_v12", TLS_PROTOCOL_TLSv1_2 );
    lauxh_pushint2tbl( L, "TLS_v1x", TLS_PROTOCOL_TLSv1 );

    return 1;
}
