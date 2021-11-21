# Config Methods For Client

create an instance of `libtls.config`.

```lua
local config = require('libtls.config')
cfg, err = config.new()
```


## ok, err = cfg:set_session_fd( fd )

sets a file descriptor to be used to manage data for TLS sessions. 

The given file descriptor must be a regular file and be owned by the current user, with permissions being restricted to only allow the owner to read and write the file (`0600`). 

If the file has a non-zero length, the client will attempt to read session data from this file and resume the previous TLS session with the server. Upon a successful handshake the file will be updated with current session data, if available. 

**NOTE:** The caller is responsible for closing this file descriptor, after all TLS contexts that have been configured to use it have been freed via tls_free().

**Parameters**

- `fd:integer`: file descriptor.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## cfg:insecure_noverifyname()

disables server name verification. Be careful when using this option.


## cfg:verify()

reenables server name and certificate verification.


## cfg:ocsp_require_stapling()

requires that a valid stapled OCSP response be provided during the TLS handshake.


## cfg:set_verify_depth( depth )

sets the maximum depth for the certificate chain verification that shall be allowed for ctx.

**Parameters**

- `depth:integer`: maximum depth for the certificate chain verification.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.
