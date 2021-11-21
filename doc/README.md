# lua-libtls module API Reference

the following descriptions are almost same as `libtls` man page.


## Constants

- [Constants in libtls module](constants.md)

## TLS Config

```lua
local config = require('libtls.config')
```

`libtls.config` module creates the configuration for the tls context.

- [libtls.config module](config.md)
  - [Config Methods For Server](server_config.md)
  - [Config Methods For Client](client_config.md)


## TLS Context

```lua
local tls = require('libtls')
```

`libtls` module creates the tls context.

- [libtls module](context.md)
    - [Creating context for server](server_context.md)
    - [Creating context for client](client_context.md)

