# lua-libtls

libtls bindings for lua.

**NOTE:** this module is under heavy development.


## Dependencies

- luarocks-fetch-gitrec: <https://github.com/siffiejoe/luarocks-fetch-gitrec>
- libressl-portable: <https://github.com/libressl-portable/portable>

---

the following descriptions are almost same as libtls man page.


## libtls module

```lua
local tls = require('libtls')
```

`libtls` module to use for the TLS connections


## Constants of libtls module

### Protocol Versions

- `TLS_v10`: TLS version 1.0
- `TLS_v11`: TLS version 1.1
- `TLS_v12`: TLS version 1.2
- `TLS_v1x`: TLS version 1.0, TLS version 1.1 and TLS version 1.2


## Creating a TLS context

### ctx, err = tls.client( cfg )

creates a new TLS context for client connections.

**Params**

- `cfg:libtls.config`: configuration object.

**Returns**

- `ctx:libtls`: client context.
- `err:string`: error message.


### ctx err = tls.server( cfg )

creates a new TLS context for server connections.

**Params**

- `cfg:libtls.config`: configuration object.

**Returns**

- `ctx:libtls`: server context.
- `err:string`: error message.


## Server context methods

### client, err = ctx:accept_fds( fdr, fdw )

creates a new client context suitable for reading and writing on an existing pair of file descriptors and returns it.

**Params**

- `fdr:number`: fd for read.
- `fdw:number`: fd for write.

**Returns**

- `client:libtls`: TLS context for client connection.
- `err:string`: error message


### client, err = ctx:accept_socket( fd )

creates a new context suitable for reading and writing on an already established socket connection and returns it.

**Params**

- `fd:number`: already established socket descriptor.

**Returns**

- `client:libtls`: TLS context for client connection.
- `err:string`: error message



## Client context methods


### ok, err = ctx:connect( host [, port] )

connects a client context to the server named by host.
If port is nil then a host of the format "hostname:port" is permitted.

**Params**

- `host:string`: hostname.
- `port:string`: port number or service name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = ctx:connect_fds( fdr, fdw [, servername] )

connects a client context to a pair of existing file descriptors.

**Params**

- `fdr:number`: fd for read.
- `fdw:number`: fd for write.
- `servername:string`:  server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = ctx:connect_servername( host [, port [, servername]] )

the same behaviour as a ctxconnect. however the name to use for verification is explicitly provided, rather than being inferred from the host value.

**Params**

- `host:string`: hostname.
- `port:string`: port number or service name.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = ctx:connect_socket( fd [, servername] )

connects a client context to an already established socket connection.

**Params**

- `fd:number`: already established socket descriptor.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### len, err, again = ctx:read( [bufsize] )

reads bufsize bytes of data from the socket.

**Params**

- `bufsize:number`: working buffer size of receive operation. (default: `BUFSIZ` that size of `stdio.h` buffers)

**Returns**

- `msg:string`: received message string.
- `err:string`: error string.
- `again:boolean`: true if got a `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`.

**NOTE:** all return values will be nil if closed by peer.


### len, err, again = ctx:write( msg )

writes message to the socket.

**Params**

- `msg:string`: message string/

**Returns**

- `len:number`: the number of bytes write.
- `err:string`: error string.
- `again:boolean`: true if got a `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`.


**NOTE:** all return values will be nil if closed by peer.


## Common methods of client and server context


### ok, err = ctx:close()

closes a connection after use.
Only the TLS layer will be shut down and the caller is responsible for closing the file descriptors, unless the connection was established using `ctx:connect()` or `ctx:connect_servername()`.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = ctx:handshake()

performs the TLS handshake.
It is only necessary to call this function if you need to guarantee that the handshake has completed, as both `ctx:read()` and `ctx:write()` will perform the TLS handshake if necessary.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok = ctx:peer_cert_provided()

checks if the peer of ctx has provided a certificate.
this method can only succeed after the handshake is complete.

**Returns**

- `ok:boolean`: true if provides.


### ok = ctx:peer_cert_contains_name()

checks if the peer of a ctx has provided a certificate that contains a SAN or CN that matches name.
this method can only succeed after the handshake is complete.

**Returns**

- `ok:boolean`: true if contains.


### hash = ctx:peer_cert_hash()

returns a string corresponding to a hash of the raw peer certificate from ctx prefixed by a hash name followed by a colon. The hash currently used is SHA256, though this could change in the future.

The hash string for a certificate in file `mycert.crt` can be generated using the commands:

```
h=$(openssl x509 -outform der -in mycert.crt | sha256)
printf "SHA256:${h}\n"
```

**Returns**

- `hash:string`: hash strings.


### iss = ctx:peer_cert_issuer()

returns a string corresponding to the issuer of the peer certificate from ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `iss:string`: issuer strings.


### sbj = ctx:peer_cert_subject()

returns a string corresponding to the subject of the peer certificate from ctx.
this mthod will only succeed after the handshake is complete.


**Returns**

- `sbj:string`: subject strings.


### period = ctx:peer_cert_notbefore()

returns the time corresponding to the start of the validity period of the peer certificate from ctx.
this method will only succeed after the handshake is complete.

**Returns**

- `period:number`: start of the validity period.


### period = ctx:peer_cert_notafter()

returns the time corresponding to the end of the validity period of the peer certificate from ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `period:number`: end of the validity period.


### ver = ctx:conn_version()

returns a string corresponding to a TLS version negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.

**Returns**

- `ver:string`: a TLS version.


### ciph = ctx:conn_cipher()

returns a string corresponding to the cipher suite negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `ciph:string`: the cipher suite strings.



## libtls.config module

```lua
local config = require('libtls.config')
```

`libtls.config` module to use for the TLS configuration.

## Loads a certificate or key

### data, err = config.load_file( file [, password] )

loads a certificate or key from disk into memory to be loaded with `config:set_ca()`, `config:set_cert()` or `config:set_key()`. A private key will be decrypted if the optional password argument is specified.

**Params**

- `file:string`: filename of certificate or key file.
- `err:string`: error message.


**Returns**

- `data:string`: loaded certificate or key data.
- `err:string`: error message.


## Creating a configuration object

### cfg, err = config.new()

allocates a new default configuration object

**Returns**

- `cfg:libtls.config`: a configuration object.
- `err:string`: error message


## Common configuration methods of client and server


### ok, err = cfg:set_ca_file( file )

sets the filename used to load a file containing the root certificates.

**Params**

- `file:string`: filename of ca file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_ca_path( path )

sets the path (directory) which should be searched for root certificates.

**Params**

- `path:string`: pathname of ca file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_ca( ca )

sets the root certificates directly from memory.

**Params**

- `ca:string`: ca data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_cert_file( file )

sets file from which the public certificate will be read.

**Params**

- `file:string`: filename of cert file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_cert( cert )

sets the public certificate directly from memory.

**Params**

- `cert:string`: cert data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_ciphers( ciphers )

sets the list of ciphers that may be used.

**Params**

- `ciphers:string`: following cipher names.
	- `secure`
	- `default` (an alias for secure)
	- `legacy`
	- `compat` (an alias for legacy)

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_key_file( file )

sets the file from which the private key will be read.

**Params**

- `file:string`: filename of key file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_key( key )

directly sets the private key from memory.

**Params**

- `key:string`: key data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_keypair_file( certfile, keyfile )

sets the files from which the public certificate and private key will be read.

**Params**

- `certfile:string`: filename of cert file.
- `keyfile:string`: filename of key file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_keypair( cert, key )

directly sets the public certificate and private key from memory.

**Params**

- `cert:string`: cert data.
- `key:string`: key data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message



### ok, err = cfg:set_protocols( protocol )

sets which versions of the protocol may be used.

**Params**

- `protocol:number`:  [protocol version constants](#protocol-versions).

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### cfg:insecure_noverifycert()

disables certificate verification. Be extremely careful when using this option.


### cfg:insecure_noverifytime()

disables validity checking of certificates. Be careful when using this option.


### cfg:verify_client()

enables client certificate verification, requiring the client to send a certificate.


### cfg:verify_client_optional()

enables client certificate verification, without requiring the client to send a certificate.

### cfg:clear_keys()

clears any secret keys from memory.


## Configuration methods for server


### cfg:prefer_ciphers_client()

prefers ciphers in the client's cipher list when selecting a cipher suite. This is considered to be less secure than preferring the server's list.


### cfg:prefer_ciphers_server()

prefers ciphers in the server's cipher list when selecting a cipher suite. This is considered to be more secure than preferring the client's list and is the default.


### ok, err = cfg:set_dheparams( params )

Tune the dheparams.

**Params**

- `params:string`: "none", "auto" or "legacy".

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


### ok, err = cfg:set_ecdhecurve( name )

Use the specified EC DHE curve.

please check the list of names that can be specified with the following command;

```sh
$ openssl ecparam -list_curves
```

**Params**

- `name:string`: "none", "auto" or any NID value understood by OBJ_txt2nid(3).

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message


## Configuration methods for client


### cfg:insecure_noverifyname()

disables server name verification. Be careful when using this option.


### cfg:verify()

reenables server name and certificate verification.


### cfg:set_verify_depth( depth )

sets the maximum depth for the certificate chain verification that shall be allowed for ctx.

**Params**

- `depth:number`: maximum depth for the certificate chain verification.

