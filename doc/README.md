# lua-libtls module API Reference

the following descriptions are almost same as `libtls` man page.


## Constants

- [Constants in libtls module](constants.md)


## Error Handling

the libtls functions/methods are return the error object created by https://github.com/mah0x211/lua-error module.

```lua
local libtls = require('libtls')
local config = require('libtls.config')

local _, err = config.load_file('hello/world')
print(err) -- ./example.lua:4: in main chunk: [libtls.ERROR:-1][load_file] Operation failure (No such file or directory)
print(err.type == libtls.ERROR) -- true

local cfg = config.new()
_, err = cfg:set_ca_file('hello/world')
print(err) -- ./example.lua:9: in main chunk: [libtls.ERROR:-1][set_ca_file] Operation failure (failed to open CA file 'hello/world': No such file or directory)
print(err.type == libtls.ERROR) -- true
```

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

