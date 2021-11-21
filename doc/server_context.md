# Server Context

### ctx err = libtls.server( cfg )

creates a new TLS context for server connections.

**Parameters**

- `cfg:libtls.config`: configuration object.

**Returns**

- `ctx:libtls`: server context.
- `err:string`: error message.


```lua
local libtls = require('libtls')
local config = require('libtls.config')

-- create config for server context
local cfg = config.new()
cfg:set_keypair_file('./cert.pem', './cert.key')
-- create server context
local ctx, err = libtls.server(cfg)
```


## client, err = ctx:accept_fds( fdr, fdw )

creates a new client context suitable for reading and writing on an existing pair of file descriptors and returns it.

**Parameters**

- `fdr:integer`: fd for read.
- `fdw:integer`: fd for write.

**Returns**

- `client:libtls`: TLS context for client connection.
- `err:string`: error message.


## client, err = ctx:accept_socket( fd )

creates a new context suitable for reading and writing on an already established socket connection and returns it.

**Parameters**

- `fd:integer`: already established socket descriptor.

**Returns**

- `client:libtls`: TLS context for client connection.
- `err:string`: error message.


## name = ctx:conn_servername()

returns a string corresponding to the servername that the client connected to ctx requested by sending a TLS Server Name Indication extension.

**Returns**

- `name:string`: servername strings.


