# Config Methods For Server

create an instance of `libtls.config`.

```lua
local config = require('libtls.config')
cfg, err = config.new()
```


## ok, err = cfg:add_keypair_file( certfile, keyfile [, staplefile] )

adds an additional public certificate, private key, and DER encoded OCSP staple from the specified files, used as an alternative certificate for Server Name Indication.

**Parameters**

- `certfile:string`: filename of cert file.
- `keyfile:string`: filename of key file.
- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:add_keypair( cert, key [, staple] )

adds an additional public certificate, private key, and DER encoded OCSP staple from memory, used as an alternative certificate for Server Name Indication

**Parameters**

- `cert:string`: cert data.
- `key:string`: key data.
- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## cfg:prefer_ciphers_client()

prefers ciphers in the client's cipher list when selecting a cipher suite. This is considered to be less secure than preferring the server's list.


## cfg:prefer_ciphers_server()

prefers ciphers in the server's cipher list when selecting a cipher suite. This is considered to be more secure than preferring the client's list and is the default.


## ok, err = cfg:set_dheparams( params )

Tune the dheparams.

**Parameters**

- `params:string`: following strings.
  - `none`
  - `auto`
  - `legacy`

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:set_ecdhecurve( name )

Use the specified EC DHE curve.

please check the list of names that can be specified with the following command;

```sh
openssl ecparam -list_curves
```

**Parameters**

- `name:string`: "none", "auto" or any NID value understood by OBJ_txt2nid(3).

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:set_ecdhecurves( names )

specifies the names of the elliptic curves that may be used during Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange. 

This is a comma separated list, given in order of preference. The special value of `default` will use the default curves (currently `X25519`, `P-256` and `P-384`). 

**NOTE:** This function replaces `set_ecdhecurve`, which is deprecated

please check the list of names that can be specified with the following command;

```sh
openssl ecparam -list_curves
```

**Parameters**

- `names:string`: comma separated list, given in order of preference.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:set_session_id( sid )

sets the session identifier that will be used by the TLS server when sessions are enabled. By default a random value is used.

**Parameters**

- `sid:string`: session identifier.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:set_session_lifetime( lifetime )

sets the lifetime to be used for TLS sessions. Session support is disabled if a lifetime of zero is specified.

**Parameters**

- `lifetime:integer`: session lifetime. (default `0`)

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = cfg:add_ticket_key( keyrev, key )

adds a key used for the encryption and authentication of TLS tickets. By default keys are generated and rotated automatically based on their lifetime. This function should only be used to synchronise ticket encryption key across multiple processes. Re-adding a known key will result in an error, unless it is the most recently added key.

**Parameters**

- `keyrev:integer`: revision number of key.
- `key:string`: key string.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.

