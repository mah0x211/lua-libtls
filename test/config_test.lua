local testcase = require('testcase')
local fileno = require('io.fileno')
local exec = require('exec').execvp
local libtls = require('libtls')
local config = require('libtls.config')

function testcase.before_all()
    local p = assert(exec('openssl', {
        'req',
        '-new',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-x509',
        '-days',
        '1',
        '-keyout',
        'cert.key',
        '-out',
        'cert.pem',
        '-subj',
        '/C=US/CN=www.example.com',
    }))

    for line in p.stderr:lines() do
        print(line)
    end

    local res = assert(p:waitpid())
    if res.exit ~= 0 then
        error('failed to generate cert files')
    end
end

function testcase.parse_protocols()
    -- test that parse protocols
    for _, v in ipairs({
        'tlsv1.0',
        'tlsv1.1',
        'tlsv1.2',
        'tlsv1.3',
        'all',
        'default',
        'legacy',
        'secure',
    }) do
        local proto, err = config.parse_protocols(v)
        assert.greater(proto, 0)
        assert.is_nil(err)
    end

    -- test that return error
    local proto, err = config.parse_protocols('foo')
    assert.equal(proto, -1)
    assert.equal(err.type, libtls.ERROR)
end

function testcase.default_ca_cert_file()
    -- test that return default ca cert file
    local file = config.default_ca_cert_file()
    assert.is_string(file)
end

function testcase.load_file()
    -- test that load cert file
    local content, err = assert(config.load_file('cert.pem'))
    assert.is_string(content)
    assert.is_nil(err)

    -- test that return error if file does not exist
    content, err = config.load_file('foo/bar/cert/file')
    assert.is_nil(content)
    assert.equal(err.type, libtls.ERROR)

    -- test that throws an error if argument is not string
    err = assert.throws(config.load_file, {})
    assert.match(err, 'string expected, got table')
end

function testcase.new()
    -- test that create new config context
    local cfg = assert(config.new())
    assert.match(tostring(cfg), '^libtls.config: ', false)
end

function testcase.add_keypair_file()
    local cfg = assert(config.new())

    -- test that add keypair file
    assert(cfg:add_keypair_file('cert.pem', 'cert.key'))

    -- test that return error if pem file does not exit
    local ok, err = cfg:add_keypair_file('hello.pem', 'cert.key')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello.pem')

    -- test that return error if key file does not exit
    ok, err = cfg:add_keypair_file('cert.pem', 'hello.key')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello.key')

    -- TODO: ocsp file

    -- test that throws an error if cert argument is invalid
    err = assert.throws(cfg.add_keypair_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)

    -- test that throws an error if key argument is invalid
    err = assert.throws(cfg.add_keypair_file, cfg, '')
    assert.match(err, 'argument #3 .+string expected', false)

    -- test that throws an error if ocsp argument is invalid
    err = assert.throws(cfg.add_keypair_file, cfg, '', '', {})
    assert.match(err, 'argument #4 .+string expected', false)
end

function testcase.add_keypair()
    local cfg = assert(config.new())
    local pem = assert(io.open('cert.pem'):read('*a'))
    local key = assert(io.open('cert.key'):read('*a'))

    -- test that add keypair
    assert(cfg:add_keypair(pem, key))
    assert(cfg:add_keypair(pem, ''))

    -- test that return error if pem file does not exit
    local ok, err = cfg:add_keypair('', key)
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'load certificate')

    -- TODO: ocsp file

    -- test that throws an error if cert argument is invalid
    err = assert.throws(cfg.add_keypair, cfg)
    assert.match(err, 'argument #2 .+string expected', false)

    -- test that throws an error if key argument is invalid
    err = assert.throws(cfg.add_keypair, cfg, '')
    assert.match(err, 'argument #3 .+string expected', false)

    -- test that throws an error if ocsp argument is invalid
    err = assert.throws(cfg.add_keypair, cfg, '', '', {})
    assert.match(err, 'argument #4 .+string expected', false)
end

function testcase.set_alpn()
    local cfg = assert(config.new())

    -- test that set alpn
    assert(cfg:set_alpn('http/2,http/1.1'))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_alpn('')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'alpn protocol')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_alpn, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ca_file()
    local cfg = assert(config.new())

    -- test that sets a ca file
    assert(cfg:set_ca_file('cert.pem'))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_ca_file('')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'CA file')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_ca_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ca_path()
    local cfg = assert(config.new())

    -- test that directory path of the root ca file
    assert(cfg:set_ca_path(''))

    -- test that throws an error if cert argument is invalid
    local err = assert.throws(cfg.set_ca_path, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ca()
    local cfg = assert(config.new())

    -- test that sets the root certificates directly
    assert(cfg:set_ca(''))

    -- test that throws an error if cert argument is invalid
    local err = assert.throws(cfg.set_ca, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_cert_file()
    local cfg = assert(config.new())

    -- test that sets a cert file
    assert(cfg:set_cert_file('cert.pem'))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_cert_file('')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'open certificate file')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_cert_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_cert()
    local cfg = assert(config.new())
    local pem = assert(io.open('cert.pem'):read('*a'))

    -- test that sets a cert file
    assert(cfg:set_cert(pem))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_cert('')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'load certificate')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_cert_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ciphers()
    local cfg = assert(config.new())

    -- test that sets the list of ciphers
    for _, v in ipairs({
        'secure',
        'compat',
        'legacy',
        'insecure',
        'HIGH:!aNULL',
    }) do
        assert(cfg:set_ciphers(v))
    end

    -- test that return error if list contains an unknown cipher
    local ok, err = cfg:set_ciphers('hello')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_ciphers, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_crl_file()
    -- TODO
end

function testcase.set_crl()
    -- TODO
end

function testcase.set_dheparams()
    local cfg = assert(config.new())

    -- test that sets parameters for DHE key exchange
    for _, v in ipairs({
        'none',
        'auto',
        'legacy',
    }) do
        assert(cfg:set_dheparams(v))
    end

    -- test that return error if list contains an unknown cipher
    local ok, err = cfg:set_dheparams('hello')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_dheparams, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ecdhecurve()
    local cfg = assert(config.new())

    -- test that sets parameters for DHE key exchange
    for _, v in ipairs({
        'none',
        'auto',
        'P-256',
    }) do
        assert(cfg:set_ecdhecurve(v))
    end

    -- test that return error if list contains an unknown cipher
    local ok, err = cfg:set_ecdhecurve('hello')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_ecdhecurve, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_ecdhecurves()
    local cfg = assert(config.new())

    -- test that sets parameters for DHE key exchange
    assert(cfg:set_ecdhecurves('P-256:P-384'))

    -- test that return error if list contains an unknown cipher
    local ok, err = cfg:set_ecdhecurves('hello')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_ecdhecurves, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_key_file()
    local cfg = assert(config.new())

    -- test that sets a key file
    assert(cfg:set_key_file('cert.key'))

    -- test that return error if key file does not exit
    local ok, err = cfg:set_key_file('')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'open key file')

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_key_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_key()
    local cfg = assert(config.new())
    local key = assert(io.open('cert.key'):read('*a'))

    -- test that sets a key file
    assert(cfg:set_key(key))
    assert(cfg:set_key(''))

    -- test that throws an error if argument is invalid
    local err = assert.throws(cfg.set_key, cfg)
    assert.match(err, 'argument #2 .+string expected', false)
end

function testcase.set_keypair_file()
    local cfg = assert(config.new())

    -- test that set keypair file
    assert(cfg:set_keypair_file('cert.pem', 'cert.key'))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_keypair_file('hello.pem', 'cert.key')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello.pem')

    -- test that return error if key file does not exit
    ok, err = cfg:set_keypair_file('cert.pem', 'hello.key')
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'hello.key')

    -- TODO: ocsp file

    -- test that throws an error if cert argument is invalid
    err = assert.throws(cfg.set_keypair_file, cfg)
    assert.match(err, 'argument #2 .+string expected', false)

    -- test that throws an error if key argument is invalid
    err = assert.throws(cfg.set_keypair_file, cfg, '')
    assert.match(err, 'argument #3 .+string expected', false)

    -- test that throws an error if ocsp argument is invalid
    err = assert.throws(cfg.set_keypair_file, cfg, '', '', {})
    assert.match(err, 'argument #4 .+string expected', false)
end

function testcase.set_keypair()
    local cfg = assert(config.new())
    local pem = assert(io.open('cert.pem'):read('*a'))
    local key = assert(io.open('cert.key'):read('*a'))

    -- test that set keypair
    assert(cfg:set_keypair(pem, key))
    assert(cfg:set_keypair(pem, ''))

    -- test that return error if pem file does not exit
    local ok, err = cfg:set_keypair('', key)
    assert.is_false(ok)
    assert.equal(err.type, libtls.ERROR)
    assert.match(err, 'load certificate')

    -- TODO: ocsp file

    -- test that throws an error if cert argument is invalid
    err = assert.throws(cfg.set_keypair, cfg)
    assert.match(err, 'argument #2 .+string expected', false)

    -- test that throws an error if key argument is invalid
    err = assert.throws(cfg.set_keypair, cfg, '')
    assert.match(err, 'argument #3 .+string expected', false)

    -- test that throws an error if ocsp argument is invalid
    err = assert.throws(cfg.set_keypair, cfg, '', '', {})
    assert.match(err, 'argument #4 .+string expected', false)
end

function testcase.set_ocsp_staple_file()
    -- TODO
end

function testcase.set_ocsp_staple()
    -- TODO
end

function testcase.set_protocols()
    local cfg = assert(config.new())

    -- test that set protocols
    assert(cfg:set_protocols(libtls.TLS_v10, libtls.TLS_v11, libtls.TLS_v12,
                             libtls.TLS_v13, libtls.TLS_v1x, libtls.TLS_DEFAULT))

    -- test that throws an error if argument is invalid
    local err = assert.throws(cfg.set_protocols, cfg, 0, {})
    assert.match(err, 'argument #3 .+integer expected', false)
end

function testcase.set_session_fd()
    local cfg = assert(config.new())
    local f = assert(io.tmpfile())
    local fd = fileno(f)

    -- test that set session fd
    assert(cfg:set_session_fd(fd))

    -- test that return error if invalid descriptor
    local ok, err = cfg:set_session_fd(-2)
    assert.is_false(ok)
    assert(err.type, libtls.ERROR)

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_session_fd, cfg, {})
    assert.match(err, 'argument #2 .+integer expected', false)
end

function testcase.set_verify_depth()
    local cfg = assert(config.new())

    -- test that set protocols
    assert(cfg:set_verify_depth(1))

    -- test that throws an error if argument is invalid
    local err = assert.throws(cfg.set_protocols, cfg, {})
    assert.match(err, 'argument #2 .+integer expected', false)
end

function testcase.prefer_ciphers_client()
    local cfg = assert(config.new())

    -- test that prefers ciphers in the client's cipher list
    assert.is_none(cfg:prefer_ciphers_client())
end

function testcase.prefer_ciphers_server()
    local cfg = assert(config.new())

    -- test that prefers ciphers in the server's cipher list
    assert.is_none(cfg:prefer_ciphers_server())
end

function testcase.insecure_noverifycert()
    local cfg = assert(config.new())

    -- test that disables certificate verification and OCSP validation
    assert.is_none(cfg:insecure_noverifycert())
end

function testcase.insecure_noverifyname()
    local cfg = assert(config.new())

    -- test that disables server name verification
    assert.is_none(cfg:insecure_noverifyname())
end

function testcase.insecure_noverifytime()
    local cfg = assert(config.new())

    -- test that disables validity checking of certificates and OCSP validation
    assert.is_none(cfg:insecure_noverifytime())
end

function testcase.verify()
    local cfg = assert(config.new())

    -- test that reenables server name and certificate verification
    assert.is_none(cfg:verify())
end

function testcase.ocsp_require_stapling()
    local cfg = assert(config.new())

    -- test that valid stapled OCSP response required
    assert.is_none(cfg:ocsp_require_stapling())
end

function testcase.verify_client()
    local cfg = assert(config.new())

    -- test that enables client certificate verification, requiring the client to send a certificate
    assert.is_none(cfg:verify_client())
end

function testcase.verify_client_optional()
    local cfg = assert(config.new())

    -- test that enables client certificate verification, without requiring the client to send a certificate
    assert.is_none(cfg:verify_client_optional())
end

function testcase.clear_keys()
    local cfg = assert(config.new())

    -- test that clears any secret keys from memory
    assert.is_none(cfg:clear_keys())
end

function testcase.set_session_id()
    -- TODO
end

function testcase.set_session_lifetime()
    local cfg = assert(config.new())

    -- test that sets the lifetime to be used for TLS sessions
    assert(cfg:set_session_lifetime(0))

    -- test that return error if litime is too small
    local ok, err = cfg:set_session_lifetime(1)
    assert.is_false(ok)
    assert(err.type, libtls.ERROR)
    assert.match(err, "too small")

    -- test that throws an error if argument is invalid
    err = assert.throws(cfg.set_session_lifetime, cfg, {})
    assert.match(err, 'argument #2 .+integer expected', false)
end

function testcase.add_ticket_key()
    -- TODO
end

