# libtls.config module

`libtls.config` module to use for the TLS configuration.

```lua
local config = require('libtls.config')
```

- [Config Methods For Server](server_config.md)
- [Config Methods For Client](client_config.md)


### Utility functions

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

**Parameters**

- `protostr:string`: error message.

**Returns**

- `vers:integer`:  [protocol version constants](#protocol-versions).


### path = config.default_ca_cert_file()

returns the path of the file that contains the default root certificates.

**Returns**

- `path:string`: pathname of default ca file.


### data, err = config.load_file( file [, password] )

loads a certificate or key from disk into memory to be loaded with `config:set_ca()`, `config:set_cert()` or `config:set_key()`. A private key will be decrypted if the optional password argument is specified.

**Parameters**

- `file:string`: filename of certificate or key file.
- `password:string`: password for key file.


**Returns**

- `data:string`: loaded certificate or key data.
- `err:error`: error object.


## cfg, err = config.new()

allocates a new default configuration object

**Returns**

- `cfg:libtls.config`: a configuration object.
- `err:error`: error object.


## ok, err = cfg:set_alpn( alpn )

sets the ALPN protocols that are supported. The alpn string is a comma separated list of protocols, in order of preference.

**Parameters**

- `alpn:string`: comma separated list of protocols.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ca_file( file )

sets the filename used to load a file containing the root certificates.

**Parameters**

- `file:string`: filename of ca file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ca_path( path )

sets the path (directory) which should be searched for root certificates.

**Parameters**

- `path:string`: pathname of ca file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ca( ca )

sets the root certificates directly from memory.

**Parameters**

- `ca:string`: ca data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_cert_file( file )

sets file from which the public certificate will be read.

**Parameters**

- `file:string`: filename of cert file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_cert( cert )

sets the public certificate directly from memory.

**Parameters**

- `cert:string`: cert data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ciphers( ciphers )

sets the list of ciphers that may be used.

**Parameters**

- `ciphers:string`: following cipher names.
  - `secure`
  - `default` (an alias for secure)
  - `legacy`
  - `compat` (an alias for legacy)
  - `insecure` (an alias for all)

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_crl_file( file )

sets the filename used to load a file containing the Certificate Revocation List (CRL).

**Parameters**

- `file:string`: filename of CRL file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_crl( crl )

sets the CRL directly from memory.

**Parameters**

- `crl:string`: CRL data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_key_file( file )

sets the file from which the private key will be read.

**Parameters**

- `file:string`: filename of key file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_key( key )

directly sets the private key from memory.

**Parameters**

- `key:string`: key data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_keypair_file( certfile, keyfile [, staplefile] )

sets the files from which the public certificate, private key, and DER encoded OCSP staple will be read.

**Parameters**

- `certfile:string`: filename of cert file.
- `keyfile:string`: filename of key file.
- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_keypair( cert, key [, staple]  )

directly sets the public certificate, private key, and DER encoded OCSP staple from memory.


**Parameters**

- `cert:string`: cert data.
- `key:string`: key data.
- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ocsp_staple( staple )

sets a DER-encoded OCSP response to be stapled during the TLS handshake from memory.

**Parameters**

- `staple:string`: OCSP staple data.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_ocsp_staple_file( staplefile )

sets a DER-encoded OCSP response to be stapled during the TLS handshake from the specified file.

**Parameters**

- `staplefile:string`: filename of OCSP staple file.

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## ok, err = cfg:set_protocols( protocol, ... )

sets which versions of the protocol may be used.

**Parameters**

- `protocol:integer`:  [protocol version constants](constants.md#protocol-versions).

**Returns**

- `ok:boolean`: `true` on success.
- `err:error`: error object.


## cfg:insecure_noverifycert()

disables certificate verification. Be extremely careful when using this option.


## cfg:insecure_noverifytime()

disables validity checking of certificates. Be careful when using this option.


## cfg:verify_client()

enables client certificate verification, requiring the client to send a certificate.


## cfg:verify_client_optional()

enables client certificate verification, without requiring the client to send a certificate.

## cfg:clear_keys()

clears any secret keys from memory.
