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
 *  src/config.c
 *  lua-libtls
 *  Created by Masatoshi Teruya on 16/07/23.
 */


#include "libtls.h"


static int clear_keys_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_clear_keys( cfg->ctx );

     return 0;
}


static int verify_client_optional_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_verify_client_optional( cfg->ctx );

     return 0;
}


static int verify_client_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_verify_client( cfg->ctx );

     return 0;
}


static int verify_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_verify( cfg->ctx );

     return 0;
}


static int insecure_noverifytime_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_insecure_noverifytime( cfg->ctx );

     return 0;
}


static int insecure_noverifyname_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_insecure_noverifyname( cfg->ctx );

     return 0;
}


static int insecure_noverifycert_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_insecure_noverifycert( cfg->ctx );

     return 0;
}


static int prefer_ciphers_server_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_prefer_ciphers_server( cfg->ctx );

     return 0;
}


static int prefer_ciphers_client_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );

     tls_config_prefer_ciphers_client( cfg->ctx );

     return 0;
}


static int set_verify_depth_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     int depth = lauxh_checkinteger( L, 2 );

     tls_config_set_verify_depth( cfg->ctx, depth );

     return 0;
}


static int set_protocols_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     uint32_t protocols = (uint32_t)lauxh_checkinteger( L, 2 );

     switch( protocols )
     {
        case TLS_PROTOCOL_TLSv1_0:
        case TLS_PROTOCOL_TLSv1_1:
        case TLS_PROTOCOL_TLSv1_2:
        case TLS_PROTOCOL_TLSv1:
            tls_config_set_protocols( cfg->ctx, protocols );
            lua_pushboolean( L, 1 );
            return 1;

        default:
             lua_pushboolean( L, 0 );
             lua_pushstring( L, strerror( EINVAL ) );
             return 2;
     }
}


static int set_keypair_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     size_t clen = 0;
     const uint8_t *cert = (const uint8_t*)lauxh_checklstring( L, 2, &clen );
     size_t klen = 0;
     const uint8_t *key = (const uint8_t*)lauxh_checklstring( L, 3, &klen );

     if( tls_config_set_keypair_mem( cfg->ctx, cert, clen, key, klen ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_keypair_file_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *cert = lauxh_checkstring( L, 2 );
     const char *key = lauxh_checkstring( L, 3 );

     if( tls_config_set_keypair_file( cfg->ctx, cert, key ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_key_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     size_t len = 0;
     const uint8_t *key = (const uint8_t*)lauxh_checklstring( L, 2, &len );

     if( tls_config_set_key_mem( cfg->ctx, key, len ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_key_file_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *file = lauxh_checkstring( L, 2 );

     if( tls_config_set_key_file( cfg->ctx, file ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_ecdhecurve_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *name = lauxh_checkstring( L, 2 );

     if( tls_config_set_ecdhecurve( cfg->ctx, name ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_dheparams_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *params = lauxh_checkstring( L, 2 );

     if( tls_config_set_dheparams( cfg->ctx, params ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_ciphers_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *ciphers = lauxh_checkstring( L, 2 );

     if( tls_config_set_ciphers( cfg->ctx, ciphers ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_cert_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     size_t len = 0;
     const uint8_t *cert = (const uint8_t*)lauxh_checklstring( L, 2, &len );

     if( tls_config_set_cert_mem( cfg->ctx, cert, len ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_cert_file_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *file = lauxh_checkstring( L, 2 );

     if( tls_config_set_cert_file( cfg->ctx, file ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_ca_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     size_t len = 0;
     const uint8_t *ca = (const uint8_t*)lauxh_checklstring( L, 2, &len );

     if( tls_config_set_ca_mem( cfg->ctx, ca, len ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_ca_path_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *path = lauxh_checkstring( L, 2 );

     if( tls_config_set_ca_path( cfg->ctx, path ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int set_ca_file_lua( lua_State *L )
{
     ltls_config_t *cfg = lauxh_checkudata( L, 1, LIBTLS_CONFIG_MT );
     const char *file = lauxh_checkstring( L, 2 );

     if( tls_config_set_ca_file( cfg->ctx, file ) ){
         lua_pushboolean( L, 0 );
         lua_pushstring( L, strerror( errno ) );
         return 2;
     }

     lua_pushboolean( L, 1 );

     return 1;
}


static int tostring_lua( lua_State *L )
{
    return TOSTRING_MT( L, LIBTLS_CONFIG_MT );
}


static int gc_lua( lua_State *L )
{
    ltls_config_t *cfg = lua_touserdata( L, 1 );

    tls_config_free( cfg->ctx );

    return 0;
}


static int new_lua( lua_State *L )
{
    ltls_config_t *cfg = lua_newuserdata( L, sizeof( ltls_config_t ) );

    if( !cfg || !( cfg->ctx = tls_config_new() ) ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    lauxh_setmetatable( L, LIBTLS_CONFIG_MT );

    return 1;
}


static int load_file_lua( lua_State *L )
{
    const char *file = lauxh_checkstring( L, 1 );
    char *pswd = (char*)lauxh_optstring( L, 2, NULL );
    size_t len = 0;
    uint8_t *content = tls_load_file( file, &len, pswd );

    if( !content ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    lua_pushlstring( L, (const char*)content, len );

    return 1;
}


LUALIB_API int luaopen_libtls_config( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "set_ca_file", set_ca_file_lua },
        { "set_ca_path", set_ca_path_lua },
        { "set_ca", set_ca_lua },

        { "set_cert_file", set_cert_file_lua },
        { "set_cert", set_cert_lua },

        { "set_ciphers", set_ciphers_lua },
        { "set_dheparams", set_dheparams_lua },
        { "set_ecdhecurve", set_ecdhecurve_lua  },

        { "set_key_file", set_key_file_lua },
        { "set_key", set_key_lua },

        { "set_keypair_file", set_keypair_file_lua },
        { "set_keypair", set_keypair_lua },

        { "set_protocols", set_protocols_lua },
        { "set_verify_depth", set_verify_depth_lua },

        { "prefer_ciphers_client", prefer_ciphers_client_lua },
        { "prefer_ciphers_server", prefer_ciphers_server_lua },

        { "insecure_noverifycert", insecure_noverifycert_lua },
        { "insecure_noverifyname", insecure_noverifyname_lua },
        { "insecure_noverifytime", insecure_noverifytime_lua },
        { "verify", verify_lua },
        { "verify_client", verify_client_lua },
        { "verify_client_optional", verify_client_optional_lua },

        { "clear_keys", clear_keys_lua },
        { NULL, NULL }
    };
    struct luaL_Reg funcs[] = {
        { "load_file", load_file_lua },
        { "new", new_lua },
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = funcs;

    // register metatable
    libtls_newmetatable( L, LIBTLS_CONFIG_MT, mmethod, method );

    // create table
    lua_newtable( L );
    while( ptr->name ){
        lauxh_pushfn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }

    return 1;
}

