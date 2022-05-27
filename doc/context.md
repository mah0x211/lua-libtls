# libtls module

`libtls` module to use for handling the TLS context.

```lua
local libtls = require('libtls')
```

- [Creating context for server](server_context.md)
- [Creating context for client](client_context.md)


## ctx:reset()

reset the TLS context that allowing for it to be reused.


## ok, err, want = ctx:close()

closes a connection after use.
Only the TLS layer will be shut down and the caller is responsible for closing the file descriptors, unless the connection was established using `ctx:connect()` or `ctx:connect_servername()`.

**Returns**

- `ok:boolean`: `true` on success.
- `err:object`: error object.
- `want:integer`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](constants.md#required-file-descriptor-states))


## ok, err, want = ctx:handshake()

performs the TLS handshake.
It is only necessary to call this function if you need to guarantee that the handshake has completed, as both `ctx:read()` and `ctx:write()` will perform the TLS handshake if necessary.

**Returns**

- `ok:boolean`: `true` on success.
- `err:object`: error object.
- `want:integer`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](constants.md#required-file-descriptor-states))


## ok = ctx:peer_cert_provided()

checks if the peer of ctx has provided a certificate.
this method can only succeed after the handshake is complete.

**Returns**

- `ok:boolean`: `true` if provides.


## ok = ctx:peer_cert_contains_name()

checks if the peer of a ctx has provided a certificate that contains a SAN or CN that matches name.
this method can only succeed after the handshake is complete.

**Returns**

- `ok:boolean`: `true` if contains.


## hash = ctx:peer_cert_hash()

returns a string corresponding to a hash of the raw peer certificate from ctx prefixed by a hash name followed by a colon. The hash currently used is SHA256, though this could change in the future.

The hash string for a certificate in file `mycert.crt` can be generated using the commands:

```sh
h=$(openssl x509 -outform der -in mycert.crt | sha256)
printf "SHA256:${h}\n"
```

**Returns**

- `hash:string`: hash strings.


## iss = ctx:peer_cert_issuer()

returns a string corresponding to the issuer of the peer certificate from ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `iss:string`: issuer strings.


## sbj = ctx:peer_cert_subject()

returns a string corresponding to the subject of the peer certificate from ctx.
this mthod will only succeed after the handshake is complete.


**Returns**

- `sbj:string`: subject strings.


## period = ctx:peer_cert_notbefore()

returns the time corresponding to the start of the validity period of the peer certificate from ctx.
this method will only succeed after the handshake is complete.

**Returns**

- `period:integer`: start of the validity period.


## period = ctx:peer_cert_notafter()

returns the time corresponding to the end of the validity period of the peer certificate from ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `period:integer`: end of the validity period.


## pem, err = ctx:peer_cert_chain_pem()

returns a PEM-encoded certificate chain for the peer certificate from ctx.

**Returns**

- `pem:string`: PEM-encoded cert chain data.
- `err:object`: error object.


## ver = ctx:conn_version()

returns a string corresponding to a TLS version negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.

**Returns**

- `ver:string`: a TLS version.


## alpn = ctx:conn_alpn_selected()

returns a string that specifies the ALPN protocol selected for use with the peer connected to ctx. If no protocol was selected then NULL is returned.


**Returns**

- `alpn:string`: ALPN protocol selected strings.


## ciph = ctx:conn_cipher()

returns a string corresponding to the cipher suite negotiated with the peer connected to ctx.
this method will only succeed after the handshake is complete.


**Returns**

- `ciph:string`: the cipher suite strings.

## bits = ctx:conn_cipher_strength()

returns the strength in bits for the symmetric cipher that is being used with the peer connected to ctx. this method will only succeed after the handshake is complete.

**Returns**

- `bits:integer`: the strength in bits.

