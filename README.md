# lua-libtls

libtls bindings for lua.

**NOTE:** this module is under heavy development.


## Dependencies

this module depends on the `libtls` library installed on your system.  
you can use either the `libressl` or `libretls` libraries.

- libressl-portable: <https://github.com/libressl-portable/portable>
- libretls: <https://git.causal.agency/libretls/about/>


## Installation

```
luarocks install libtls
```

---

the following descriptions are almost same as libtls man page.


## libtls module

```lua
local tls = require('libtls')
```

`libtls` module to use for the TLS connections


## Constants of libtls module

### Required file descriptor states

- `WANT_POLLIN`: The underlying read file descriptor needs to be readable in order to continue.
- `WANT_POLLOUT`: The underlying write file descriptor needs to be writeable in order to continue.


### Protocol Versions

- `TLS_v10`: TLS version 1.0
- `TLS_v11`: TLS version 1.1
- `TLS_v12`: TLS version 1.2
- `TLS_v1x`: TLS version 1.0, 1.1, 1.2 and 1.3
- `TLS_DEFAULT`: TLS version 1.2 and 1.3

### OCSP certificate status code

- `OCSP_CERT_GOOD`
- `OCSP_CERT_REVOKED`
- `OCSP_CERT_UNKNOWN`


### OCSP response status code

- `OCSP_RESPONSE_SUCCESSFUL`
- `OCSP_RESPONSE_MALFORMED`
- `OCSP_RESPONSE_INTERNALERROR`
- `OCSP_RESPONSE_TRYLATER`
- `OCSP_RESPONSE_SIGREQUIRED`
- `OCSP_RESPONSE_UNAUTHORIZED`


### CTL reason status code

- `CRL_REASON_UNSPECIFIED`
- `CRL_REASON_KEY_COMPROMISE`
- `CRL_REASON_CA_COMPROMISE`
- `CRL_REASON_AFFILIATION_CHANGED`
- `CRL_REASON_SUPERSEDED`
- `CRL_REASON_CESSATION_OF_OPERATION`
- `CRL_REASON_CERTIFICATE_HOLD`
- `CRL_REASON_REMOVE_FROM_CRL`
- `CRL_REASON_PRIVILEGE_WITHDRAWN`
- `CRL_REASON_AA_COMPROMISE`

### misc

- `TLS_API`
- `MAX_SESSION_ID_LENGTH`
- `TICKET_KEY_SIZE`


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
- `err:string`: error message.


### client, err = ctx:accept_socket( fd )

creates a new context suitable for reading and writing on an already established socket connection and returns it.

**Params**

- `fd:number`: already established socket descriptor.

**Returns**

- `client:libtls`: TLS context for client connection.
- `err:string`: error message.


### name = ctx:conn_servername()

returns a string corresponding to the servername that the client connected to ctx requested by sending a TLS Server Name Indication extension.

**Returns**

- `name:string`: servername strings.



## Client context methods


### ok, err = ctx:connect( host [, port] )

connects a client context to the server named by host.
If port is nil then a host of the format "hostname:port" is permitted.

**Params**

- `host:string`: hostname.
- `port:string`: port number or service name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = ctx:connect_fds( fdr, fdw [, servername] )

connects a client context to a pair of existing file descriptors.

**Params**

- `fdr:number`: fd for read.
- `fdw:number`: fd for write.
- `servername:string`:  server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = ctx:connect_servername( host [, port [, servername]] )

the same behaviour as a ctxconnect. however the name to use for verification is explicitly provided, rather than being inferred from the host value.

**Params**

- `host:string`: hostname.
- `port:string`: port number or service name.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = ctx:connect_socket( fd [, servername] )

connects a client context to an already established socket connection.

**Params**

- `fd:number`: already established socket descriptor.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### len, err, again, want = ctx:read( [bufsize] )

reads bufsize bytes of data from the socket.

**Params**

- `bufsize:number`: working buffer size of receive operation. (default: `BUFSIZ` that size of `stdio.h` buffers)

**Returns**

- `msg:string`: received message string.
- `err:string`: error string.
- `again:boolean`: true if got a `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`.
- `want:number`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](#required-file-descriptor-states))

**NOTE:** all return values will be nil if closed by peer.


### len, err, again, want = ctx:write( msg )

writes message to the socket.

**Params**

- `msg:string`: message string.

**Returns**

- `len:number`: the number of bytes write.
- `err:string`: error string.
- `again:bool`: true if all data has not been sent.
- `want:number`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](#required-file-descriptor-states))


**NOTE:** all return values will be nil if closed by peer.


### len, err, again, want = ctx:sendfile( f, bytes [, offset] )

send a file to the socket

**Parameters**

- `f:integer|file`: file descriptor or lua file handle.
- `bytes:integer`: how many bytes of the file should be sent.
- `offset:integer`: specifies where to begin in the file (default 0).

**Returns**

- `len:number`: number of bytes sent.
- `err:string`: error string.
- `again:boolean`: true if len != bytes, or errno is EAGAIN, EWOULDBLOCK or EINTR.
- `want:number`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](#required-file-descriptor-states))

**NOTE:** all return values will be nil if closed by peer.


### ok = ctx:conn_session_resumed()

indicates whether a TLS session has been resumed during the handshake with the server connected to ctx.

**Returns**

- `ok:boolean`: true if a TLS session was resumed.


### ok, err = ctx:ocsp_process_response( res )

processes a raw OCSP response in response of size size to check the revocation status of the peer certificate from ctx. A successful return true indicates that the certificate has not been revoked.

**Params**

- `res:string`: response string.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error string.


### status, err = ctx:peer_ocsp_cert_status()

returns the OCSP certificate status code as per RFC 6960 section 2.2.

**Returns**

- `status:number`: [OCSP certificate status code constants](#ocsp-certificate-status-code), or nil on error.
- `err:string`: error string.


### status, err = ctx:peer_ocsp_crl_reason()

returns the OCSP certificate revocation reason status code as per RFC 5280 section 5.3.1.

**Returns**

- `reason:number`: [CTL reason status code constants](#ctl-reason-status-code), or nil on error.
- `err:string`: error string.


### epoch, err = ctx:peer_ocsp_next_update()

returns the OCSP next update time.

**Returns**

- `epoch:number`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


### status, err = ctx:peer_ocsp_response_status()

returns the OCSP response status as per RFC 6960 section 2.3.

**Returns**

- `statis:number`: [OCSP response status code](#ocsp-response-status-code), or nil on error.
- `err:string`: error string.


### res, err = ctx:peer_ocsp_result()

returns the message string of OCSP response status, OCSP certificate status or OCSP certificate revocation reason status.

**Returns**

- `res:string`: message string or nil on error.
- `err:string`: error string.


### epoch, err = ctx:peer_ocsp_revocation_time()

returns the OCSP revocation time.

**Returns**

- `epoch:number`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


### epoch, err = ctx:peer_ocsp_this_update()

returns the OCSP this update time.

**Returns**

- `epoch:number`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


### url, err = ctx:peer_ocsp_url()

returns the URL for OCSP validation of the peer certificate from ctx.

**Returns**

- `url:string`: url string.
- `err:string`: error string.



## Common methods of client and server context

### ctx:reset()

reset the TLS context that allowing for it to be reused.


### ok, err = ctx:close()

closes a connection after use.
Only the TLS layer will be shut down and the caller is responsible for closing the file descriptors, unless the connection was established using `ctx:connect()` or `ctx:connect_servername()`.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err, want = ctx:handshake()

performs the TLS handshake.
It is only necessary to call this function if you need to guarantee that the handshake has completed, as both `ctx:read()` and `ctx:write()` will perform the TLS handshake if necessary.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.
- `want:number`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](#required-file-descriptor-states))


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


### pem, err = ctx:peer_cert_chain_pem()

returns a PEM-encoded certificate chain for the peer certificate from ctx.

**Returns**

- `pem:string`: PEM-encoded cert chain data.
- `err:string`: error message.


### ver = ctx:conn_version()

returns a string corresponding to a TLS version negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.

**Returns**

- `ver:string`: a TLS version.


### alpn = ctx:conn_alpn_selected()

returns a string that specifies the ALPN protocol selected for use with the peer connected to ctx. If no protocol was selected then NULL is returned.


**Returns**

- `alpn:string`: ALPN protocol selected strings.


### ciph = ctx:conn_cipher()

returns a string corresponding to the cipher suite negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `ciph:string`: the cipher suite strings.

### bits = ctx:conn_cipher_strength()

returns the strength in bits for the symmetric cipher that is being used with the peer connected to ctx. this method will only succeed after the handshake is complete.

**Returns**

- `bits:integer`: the strength in bits.



## libtls.config module

```lua
local config = require('libtls.config')
```

`libtls.config` module to use for the TLS configuration.


## Utility functions

### vers = config.parse_protocols( protostr )

parses a protocol string and returns the corresponding value. this value can then be passed to the [config:set_protocols](#ok-err--cfgset_protocols-protocol-) method. 

The protocol string `protostr` is a comma or colon separated list of keywords.  
Valid keywords are:

- `tlsv1.0`
- `tlsv1.1`
- `tlsv1.2`
- `tlsv1.3`
- `all` (all supported protocols)
- `default` (an alias for `secure`)
- `legacy` (an alias for `all`)
- `secure` (currently TLSv1.2 and TLSv1.3)

**Params**

- `protostr:string`: error message.

**Returns**

- `vers:integer`:  [protocol version constants](#protocol-versions).


### path = config.default_ca_cert_file()

returns the path of the file that contains the default root certificates.

**Returns**

- `path:string`: pathname of default ca file.


### data, err = config.load_file( file [, password] )

loads a certificate or key from disk into memory to be loaded with `config:set_ca()`, `config:set_cert()` or `config:set_key()`. A private key will be decrypted if the optional password argument is specified.

**Params**

- `file:string`: filename of certificate or key file.
- `password:string`: password for key file.


**Returns**

- `data:string`: loaded certificate or key data.
- `err:string`: error message.


## Creating a configuration object

### cfg, err = config.new()

allocates a new default configuration object

**Returns**

- `cfg:libtls.config`: a configuration object.
- `err:string`: error message.


## Common configuration methods of client and server


### ok, err = cfg:set_alpn( alpn )

sets the ALPN protocols that are supported. The alpn string is a comma separated list of protocols, in order of preference.

**Params**

- `alpn:string`: comma separated list of protocols.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ca_file( file )

sets the filename used to load a file containing the root certificates.

**Params**

- `file:string`: filename of ca file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ca_path( path )

sets the path (directory) which should be searched for root certificates.

**Params**

- `path:string`: pathname of ca file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ca( ca )

sets the root certificates directly from memory.

**Params**

- `ca:string`: ca data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_cert_file( file )

sets file from which the public certificate will be read.

**Params**

- `file:string`: filename of cert file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_cert( cert )

sets the public certificate directly from memory.

**Params**

- `cert:string`: cert data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ciphers( ciphers )

sets the list of ciphers that may be used.

**Params**

- `ciphers:string`: following cipher names.
  - `secure`
  - `default` (an alias for secure)
  - `legacy`
  - `compat` (an alias for legacy)
  - `insecure` (an alias for all)

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_crl_file( file )

sets the filename used to load a file containing the Certificate Revocation List (CRL).

**Params**

- `file:string`: filename of CRL file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_crl( crl )

sets the CRL directly from memory.

**Params**

- `crl:string`: CRL data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.



### ok, err = cfg:set_key_file( file )

sets the file from which the private key will be read.

**Params**

- `file:string`: filename of key file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_key( key )

directly sets the private key from memory.

**Params**

- `key:string`: key data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_keypair_file( certfile, keyfile [, staplefile] )

sets the files from which the public certificate, private key, and DER encoded OCSP staple will be read.

**Params**

- `certfile:string`: filename of cert file.
- `keyfile:string`: filename of key file.
- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_keypair( cert, key [, staple]  )

directly sets the public certificate, private key, and DER encoded OCSP staple from memory.


**Params**

- `cert:string`: cert data.
- `key:string`: key data.
- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ocsp_staple( staple )

sets a DER-encoded OCSP response to be stapled during the TLS handshake from memory.

**Params**

- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_ocsp_staple_file( staplefile )

sets a DER-encoded OCSP response to be stapled during the TLS handshake from the specified file.

**Params**

- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_protocols( protocol, ... )

sets which versions of the protocol may be used.

**Params**

- `protocol:integer`:  [protocol version constants](#protocol-versions).

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


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


### ok, err = cfg:add_keypair_file( certfile, keyfile [, staplefile] )

adds an additional public certificate, private key, and DER encoded OCSP staple from the specified files, used as an alternative certificate for Server Name Indication.

**Params**

- `certfile:string`: filename of cert file.
- `keyfile:string`: filename of key file.
- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:add_keypair( cert, key [, staple] )

adds an additional public certificate, private key, and DER encoded OCSP staple from memory, used as an alternative certificate for Server Name Indication

**Params**

- `cert:string`: cert data.
- `key:string`: key data.
- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### cfg:prefer_ciphers_client()

prefers ciphers in the client's cipher list when selecting a cipher suite. This is considered to be less secure than preferring the server's list.


### cfg:prefer_ciphers_server()

prefers ciphers in the server's cipher list when selecting a cipher suite. This is considered to be more secure than preferring the client's list and is the default.


### ok, err = cfg:set_dheparams( params )

Tune the dheparams.

**Params**

- `params:string`: following strings.
  - `none`
  - `auto`
  - `legacy`

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


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
- `err:string`: error message.


### ok, err = cfg:set_ecdhecurves( names )

specifies the names of the elliptic curves that may be used during Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange. 

This is a comma separated list, given in order of preference. The special value of `default` will use the default curves (currently `X25519`, `P-256` and `P-384`). 

**NOTE:** This function replaces `set_ecdhecurve`, which is deprecated

please check the list of names that can be specified with the following command;

```sh
$ openssl ecparam -list_curves
```

**Params**

- `names:string`: comma separated list, given in order of preference.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_session_id( sid )

sets the session identifier that will be used by the TLS server when sessions are enabled. By default a random value is used.

**Params**

- `sid:string`: session identifier.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:set_session_lifetime( lifetime )

sets the lifetime to be used for TLS sessions. Session support is disabled if a lifetime of zero is specified.

**Params**

- `lifetime:number`: session lifetime. (default `0`)

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### ok, err = cfg:add_ticket_key( keyrev, key )

adds a key used for the encryption and authentication of TLS tickets. By default keys are generated and rotated automatically based on their lifetime. This function should only be used to synchronise ticket encryption key across multiple processes. Re-adding a known key will result in an error, unless it is the most recently added key.

**Params**

- `keyrev:number`: revision number of key.
- `key:string`: key string.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.



## Configuration methods for client


### ok, err = cfg:set_session_fd( fd )

sets a file descriptor to be used to manage data for TLS sessions. 

The given file descriptor must be a regular file and be owned by the current user, with permissions being restricted to only allow the owner to read and write the file (`0600`). 

If the file has a non-zero length, the client will attempt to read session data from this file and resume the previous TLS session with the server. Upon a successful handshake the file will be updated with current session data, if available. 

**NOTE:** The caller is responsible for closing this file descriptor, after all TLS contexts that have been configured to use it have been freed via tls_free().

**Params**

- `fd:number`: file descriptor.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.


### cfg:insecure_noverifyname()

disables server name verification. Be careful when using this option.


### cfg:verify()

reenables server name and certificate verification.


### cfg:ocsp_require_stapling()

requires that a valid stapled OCSP response be provided during the TLS handshake.


### cfg:set_verify_depth( depth )

sets the maximum depth for the certificate chain verification that shall be allowed for ctx.

**Params**

- `depth:number`: maximum depth for the certificate chain verification.

**Returns**

- `ok:boolean`: true on success.
- `err:string`: error message.

