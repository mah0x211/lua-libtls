# Client Context

### ctx, err = libtls.client( cfg )

creates a new TLS context for client connections.

**Parameters**

- `cfg:libtls.config`: configuration object.

**Returns**

- `ctx:libtls`: client context.
- `err:string`: error message.


```lua
local libtls = require('libtls')
local config = require('libtls.config')

-- create config for client
local cfg = config.new()
cfg:insecure_noverifycert()
cfg:insecure_noverifyname()
-- create context for client
local ctx, err = libtls.client(cfg)
```


## ok, err = ctx:connect( host [, port] )

connects a client context to the server named by host. if port is `nil` then a `host` of the format `"hostname:port"` is permitted.

**Parameters**

- `host:string`: hostname.
- `port:string`: port number or a service name listed in services(5).

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = ctx:connect_fds( fdr, fdw [, servername] )

connects a client context to a pair of existing file descriptors.

**Parameters**

- `fdr:integer`: fd for read.
- `fdw:integer`: fd for write.
- `servername:string`:  server name.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = ctx:connect_servername( host [, port [, servername]] )

the same behaviour as a ctxconnect. however the name to use for verification is explicitly provided, rather than being inferred from the host value.

**Parameters**

- `host:string`: hostname.
- `port:string`: port number or service name.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## ok, err = ctx:connect_socket( fd [, servername] )

connects a client context to an already established socket connection.

**Parameters**

- `fd:integer`: already established socket descriptor.
- `servername:string`: server name.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error message.


## len, err, again, want = ctx:read( [bufsize] )

reads bufsize bytes of data from the socket.

**Parameters**

- `bufsize:integer`: working buffer size of receive operation. (default: `BUFSIZ` that size of `stdio.h` buffers)

**Returns**

- `msg:string`: received message string.
- `err:string`: error string.
- `again:boolean`: `true` if got a `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`.
- `want:integer`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](constants.md#required-file-descriptor-states))

**NOTE:** all return values will be nil if closed by peer.


## len, err, again, want = ctx:write( msg )

writes message to the socket.

**Parameters**

- `msg:string`: message string.

**Returns**

- `len:integer`: the number of bytes write.
- `err:string`: error string.
- `again:bool`: `true` if all data has not been sent.
- `want:integer`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](constants.md#required-file-descriptor-states))


**NOTE:** all return values will be nil if closed by peer.


## len, err, again, want = ctx:sendfile( f, bytes [, offset] )

send a file to the socket

**Parameters**

- `f:integer|file`: file descriptor or lua file handle.
- `bytes:integer`: how many bytes of the file should be sent.
- `offset:integer`: specifies where to begin in the file (default 0).

**Returns**

- `len:integer`: number of bytes sent.
- `err:string`: error string.
- `again:boolean`: `true` if len != bytes, or errno is EAGAIN, EWOULDBLOCK or EINTR.
- `want:integer`: socket descriptor states required to be `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`. (pleese see: [Required file descriptor states](constants.md#required-file-descriptor-states))

**NOTE:** all return values will be nil if closed by peer.


## ok = ctx:conn_session_resumed()

indicates whether a TLS session has been resumed during the handshake with the server connected to ctx.

**Returns**

- `ok:boolean`: `true` if a TLS session was resumed.


## ok, err = ctx:ocsp_process_response( res )

processes a raw OCSP response in response of size size to check the revocation status of the peer certificate from ctx. A successful return `true` indicates that the certificate has not been revoked.

**Parameters**

- `res:string`: response string.

**Returns**

- `ok:boolean`: `true` on success.
- `err:string`: error string.


## status, err = ctx:peer_ocsp_cert_status()

returns the OCSP certificate status code as per RFC 6960 section 2.2.

**Returns**

- `status:integer`: [OCSP certificate status code constants](constants.md#ocsp-certificate-status-code), or nil on error.
- `err:string`: error string.


## status, err = ctx:peer_ocsp_crl_reason()

returns the OCSP certificate revocation reason status code as per RFC 5280 section 5.3.1.

**Returns**

- `reason:integer`: [CTL reason status code constants](constants.md#ctl-reason-status-code), or nil on error.
- `err:string`: error string.


## epoch, err = ctx:peer_ocsp_next_update()

returns the OCSP next update time.

**Returns**

- `epoch:integer`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


## status, err = ctx:peer_ocsp_response_status()

returns the OCSP response status as per RFC 6960 section 2.3.

**Returns**

- `statuss:integer`: [OCSP response status code](constants.md#ocsp-response-status-code), or nil on error.
- `err:string`: error string.


## res, err = ctx:peer_ocsp_result()

returns the message string of OCSP response status, OCSP certificate status or OCSP certificate revocation reason status.

**Returns**

- `res:string`: message string or nil on error.
- `err:string`: error string.


## epoch, err = ctx:peer_ocsp_revocation_time()

returns the OCSP revocation time.

**Returns**

- `epoch:integer`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


## epoch, err = ctx:peer_ocsp_this_update()

returns the OCSP this update time.

**Returns**

- `epoch:integer`: a time in epoch-seconds on success or nil on error.
- `err:string`: error string.


## url, err = ctx:peer_ocsp_url()

returns the URL for OCSP validation of the peer certificate from ctx.

**Returns**

- `url:string`: url string.
- `err:string`: error string.

