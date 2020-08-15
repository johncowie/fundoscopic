#! /usr/bin/env node
(function prelude(content, deps, entry) {
  var cache = {}

  function load(file) {
    var d = deps[file]
    if (cache[file]) return cache[file].exports
    if (!d) return require(file)
    var fn = content[d[0]] //the actual module
    var module = (cache[file] = {
      exports: {},
      parent: file !== entry,
      require: require
    })
    cache[file] = module
    var resolved = require('path').resolve(file)
    var dirname = require('path').dirname(resolved)
    fn.call(
      module.exports,
      function(m) {
        if (!d[1][m]) return require(m)
        else return load(d[1][m])
      },
      module,
      module.exports,
      dirname,
      resolved
    )
    return cache[file].exports
  }

  return load(entry)
})({
"+HSmI+SqU2xLFtIyb1L+SgZI9uF1S4iwpXKqdubj0W0=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var dns = require('dns')

var defaults = require('./defaults')

var parse = require('pg-connection-string').parse // parses a connection string

var val = function (key, config, envVar) {
  if (envVar === undefined) {
    envVar = process.env['PG' + key.toUpperCase()]
  } else if (envVar === false) {
    // do nothing ... use false
  } else {
    envVar = process.env[envVar]
  }

  return config[key] || envVar || defaults[key]
}

var readSSLConfigFromEnvironment = function () {
  switch (process.env.PGSSLMODE) {
    case 'disable':
      return false
    case 'prefer':
    case 'require':
    case 'verify-ca':
    case 'verify-full':
      return true
    case 'no-verify':
      return { rejectUnauthorized: false }
  }
  return defaults.ssl
}

var ConnectionParameters = function (config) {
  // if a string is passed, it is a raw connection string so we parse it into a config
  config = typeof config === 'string' ? parse(config) : config || {}

  // if the config has a connectionString defined, parse IT into the config we use
  // this will override other default values with what is stored in connectionString
  if (config.connectionString) {
    config = Object.assign({}, config, parse(config.connectionString))
  }

  this.user = val('user', config)
  this.database = val('database', config)

  if (this.database === undefined) {
    this.database = this.user
  }

  this.port = parseInt(val('port', config), 10)
  this.host = val('host', config)

  // "hiding" the password so it doesn't show up in stack traces
  // or if the client is console.logged
  Object.defineProperty(this, 'password', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: val('password', config),
  })

  this.binary = val('binary', config)
  this.options = val('options', config)

  this.ssl = typeof config.ssl === 'undefined' ? readSSLConfigFromEnvironment() : config.ssl

  // support passing in ssl=no-verify via connection string
  if (this.ssl === 'no-verify') {
    this.ssl = { rejectUnauthorized: false }
  }

  this.client_encoding = val('client_encoding', config)
  this.replication = val('replication', config)
  // a domain socket begins with '/'
  this.isDomainSocket = !(this.host || '').indexOf('/')

  this.application_name = val('application_name', config, 'PGAPPNAME')
  this.fallback_application_name = val('fallback_application_name', config, false)
  this.statement_timeout = val('statement_timeout', config, false)
  this.idle_in_transaction_session_timeout = val('idle_in_transaction_session_timeout', config, false)
  this.query_timeout = val('query_timeout', config, false)

  if (config.connectionTimeoutMillis === undefined) {
    this.connect_timeout = process.env.PGCONNECT_TIMEOUT || 0
  } else {
    this.connect_timeout = Math.floor(config.connectionTimeoutMillis / 1000)
  }

  if (config.keepAlive === false) {
    this.keepalives = 0
  } else if (config.keepAlive === true) {
    this.keepalives = 1
  }

  if (typeof config.keepAliveInitialDelayMillis === 'number') {
    this.keepalives_idle = Math.floor(config.keepAliveInitialDelayMillis / 1000)
  }
}

// Convert arg to a string, surround in single quotes, and escape single quotes and backslashes
var quoteParamValue = function (value) {
  return "'" + ('' + value).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'"
}

var add = function (params, config, paramName) {
  var value = config[paramName]
  if (value !== undefined && value !== null) {
    params.push(paramName + '=' + quoteParamValue(value))
  }
}

ConnectionParameters.prototype.getLibpqConnectionString = function (cb) {
  var params = []
  add(params, this, 'user')
  add(params, this, 'password')
  add(params, this, 'port')
  add(params, this, 'application_name')
  add(params, this, 'fallback_application_name')
  add(params, this, 'connect_timeout')
  add(params, this, 'options')

  var ssl = typeof this.ssl === 'object' ? this.ssl : this.ssl ? { sslmode: this.ssl } : {}
  add(params, ssl, 'sslmode')
  add(params, ssl, 'sslca')
  add(params, ssl, 'sslkey')
  add(params, ssl, 'sslcert')
  add(params, ssl, 'sslrootcert')

  if (this.database) {
    params.push('dbname=' + quoteParamValue(this.database))
  }
  if (this.replication) {
    params.push('replication=' + quoteParamValue(this.replication))
  }
  if (this.host) {
    params.push('host=' + quoteParamValue(this.host))
  }
  if (this.isDomainSocket) {
    return cb(null, params.join(' '))
  }
  if (this.client_encoding) {
    params.push('client_encoding=' + quoteParamValue(this.client_encoding))
  }
  dns.lookup(this.host, function (err, address) {
    if (err) return cb(err, null)
    params.push('hostaddr=' + quoteParamValue(address))
    return cb(null, params.join(' '))
  })
}

module.exports = ConnectionParameters

},
"+ZGwpBEZvODvu0cSddvQLeMaef5vh/j15WeONzoPFic=":
function (require, module, exports, __dirname, __filename) {
'use strict';

// selected so (BASE - 1) * 0x100000000 + 0xffffffff is a safe integer
var BASE = 1000000;

function readInt8(buffer) {
	var high = buffer.readInt32BE(0);
	var low = buffer.readUInt32BE(4);
	var sign = '';

	if (high < 0) {
		high = ~high + (low === 0);
		low = (~low + 1) >>> 0;
		sign = '-';
	}

	var result = '';
	var carry;
	var t;
	var digits;
	var pad;
	var l;
	var i;

	{
		carry = high % BASE;
		high = high / BASE >>> 0;

		t = 0x100000000 * carry + low;
		low = t / BASE >>> 0;
		digits = '' + (t - BASE * low);

		if (low === 0 && high === 0) {
			return sign + digits + result;
		}

		pad = '';
		l = 6 - digits.length;

		for (i = 0; i < l; i++) {
			pad += '0';
		}

		result = pad + digits + result;
	}

	{
		carry = high % BASE;
		high = high / BASE >>> 0;

		t = 0x100000000 * carry + low;
		low = t / BASE >>> 0;
		digits = '' + (t - BASE * low);

		if (low === 0 && high === 0) {
			return sign + digits + result;
		}

		pad = '';
		l = 6 - digits.length;

		for (i = 0; i < l; i++) {
			pad += '0';
		}

		result = pad + digits + result;
	}

	{
		carry = high % BASE;
		high = high / BASE >>> 0;

		t = 0x100000000 * carry + low;
		low = t / BASE >>> 0;
		digits = '' + (t - BASE * low);

		if (low === 0 && high === 0) {
			return sign + digits + result;
		}

		pad = '';
		l = 6 - digits.length;

		for (i = 0; i < l; i++) {
			pad += '0';
		}

		result = pad + digits + result;
	}

	{
		carry = high % BASE;
		t = 0x100000000 * carry + low;
		digits = '' + t % BASE;

		return sign + digits + result;
	}
}

module.exports = readInt8;

},
"+i8bLWxSsnBNAWTDA9N82doCAwqCkHZLeUvNj8UmodI=":
function (require, module, exports, __dirname, __filename) {
module.exports = {
  "_from": "pg",
  "_id": "pg@8.3.0",
  "_inBundle": false,
  "_integrity": "sha512-jQPKWHWxbI09s/Z9aUvoTbvGgoj98AU7FDCcQ7kdejupn/TcNpx56v2gaOTzXkzOajmOEJEdi9eTh9cA2RVAjQ==",
  "_location": "/pg",
  "_phantomChildren": {},
  "_requested": {
    "type": "tag",
    "registry": true,
    "raw": "pg",
    "name": "pg",
    "escapedName": "pg",
    "rawSpec": "",
    "saveSpec": null,
    "fetchSpec": "latest"
  },
  "_requiredBy": [
    "#USER",
    "/"
  ],
  "_resolved": "https://registry.npmjs.org/pg/-/pg-8.3.0.tgz",
  "_shasum": "941383300d38eef51ecb88a0188cec441ab64d81",
  "_spec": "pg",
  "_where": "/Users/johncowie/Projects/purescript/fundoscopic",
  "author": {
    "name": "Brian Carlson",
    "email": "brian.m.carlson@gmail.com"
  },
  "bugs": {
    "url": "https://github.com/brianc/node-postgres/issues"
  },
  "bundleDependencies": false,
  "dependencies": {
    "buffer-writer": "2.0.0",
    "packet-reader": "1.0.0",
    "pg-connection-string": "^2.3.0",
    "pg-pool": "^3.2.1",
    "pg-protocol": "^1.2.5",
    "pg-types": "^2.1.0",
    "pgpass": "1.x",
    "semver": "4.3.2"
  },
  "deprecated": false,
  "description": "PostgreSQL client - pure javascript & libpq with the same API",
  "devDependencies": {
    "async": "0.9.0",
    "bluebird": "3.5.2",
    "co": "4.6.0",
    "pg-copy-streams": "0.3.0"
  },
  "engines": {
    "node": ">= 8.0.0"
  },
  "files": [
    "lib",
    "SPONSORS.md"
  ],
  "homepage": "https://github.com/brianc/node-postgres",
  "keywords": [
    "database",
    "libpq",
    "pg",
    "postgre",
    "postgres",
    "postgresql",
    "rdbms"
  ],
  "license": "MIT",
  "main": "./lib",
  "minNativeVersion": "2.0.0",
  "name": "pg",
  "repository": {
    "type": "git",
    "url": "git://github.com/brianc/node-postgres.git"
  },
  "scripts": {
    "test": "make test-all"
  },
  "version": "8.3.0"
}

},
"+uyHj7tA8xmRjCjRC3KUOBJMM3Xd1+Nlzejd1JiM6yQ=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var Client = require('./client')
var defaults = require('./defaults')
var Connection = require('./connection')
var Pool = require('pg-pool')

const poolFactory = (Client) => {
  return class BoundPool extends Pool {
    constructor(options) {
      super(options, Client)
    }
  }
}

var PG = function (clientConstructor) {
  this.defaults = defaults
  this.Client = clientConstructor
  this.Query = this.Client.Query
  this.Pool = poolFactory(this.Client)
  this._pools = []
  this.Connection = Connection
  this.types = require('pg-types')
}

if (typeof process.env.NODE_PG_FORCE_NATIVE !== 'undefined') {
  module.exports = new PG(require('./native'))
} else {
  module.exports = new PG(Client)

  // lazy require native module...the native module may not have installed
  Object.defineProperty(module.exports, 'native', {
    configurable: true,
    enumerable: false,
    get() {
      var native = null
      try {
        native = new PG(require('./native'))
      } catch (err) {
        if (err.code !== 'MODULE_NOT_FOUND') {
          throw err
        }
        /* eslint-disable no-console */
        console.error(err.message)
        /* eslint-enable no-console */
      }

      // overwrite module.exports.native so that getter is never called again
      Object.defineProperty(module.exports, 'native', {
        value: native,
      })

      return native
    },
  })
}

},
"1Vghz64laF+FchvSchAuGp3d0LL3SDMka6iAYxKOMfU=":
function (require, module, exports, __dirname, __filename) {
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const emptyBuffer = Buffer.allocUnsafe(0);
class BufferReader {
    constructor(offset = 0) {
        this.offset = offset;
        this.buffer = emptyBuffer;
        // TODO(bmc): support non-utf8 encoding?
        this.encoding = 'utf-8';
    }
    setBuffer(offset, buffer) {
        this.offset = offset;
        this.buffer = buffer;
    }
    int16() {
        const result = this.buffer.readInt16BE(this.offset);
        this.offset += 2;
        return result;
    }
    byte() {
        const result = this.buffer[this.offset];
        this.offset++;
        return result;
    }
    int32() {
        const result = this.buffer.readInt32BE(this.offset);
        this.offset += 4;
        return result;
    }
    string(length) {
        const result = this.buffer.toString(this.encoding, this.offset, this.offset + length);
        this.offset += length;
        return result;
    }
    cstring() {
        const start = this.offset;
        let end = start;
        while (this.buffer[end++] !== 0) { }
        this.offset = end;
        return this.buffer.toString(this.encoding, start, end - 1);
    }
    bytes(length) {
        const result = this.buffer.slice(this.offset, this.offset + length);
        this.offset += length;
        return result;
    }
}
exports.BufferReader = BufferReader;
//# sourceMappingURL=buffer-reader.js.map
},
"5iKT6HG91adEn/PHlWyVNuwdLqc2lGHedzIrUla7k+c=":
function (require, module, exports, __dirname, __filename) {

/**
 * Module dependencies.
 */

var sep = require('path').sep || '/';

/**
 * Module exports.
 */

module.exports = fileUriToPath;

/**
 * File URI to Path function.
 *
 * @param {String} uri
 * @return {String} path
 * @api public
 */

function fileUriToPath (uri) {
  if ('string' != typeof uri ||
      uri.length <= 7 ||
      'file://' != uri.substring(0, 7)) {
    throw new TypeError('must pass in a file:// URI to convert to a file path');
  }

  var rest = decodeURI(uri.substring(7));
  var firstSlash = rest.indexOf('/');
  var host = rest.substring(0, firstSlash);
  var path = rest.substring(firstSlash + 1);

  // 2.  Scheme Definition
  // As a special case, <host> can be the string "localhost" or the empty
  // string; this is interpreted as "the machine from which the URL is
  // being interpreted".
  if ('localhost' == host) host = '';

  if (host) {
    host = sep + sep + host;
  }

  // 3.2  Drives, drive letters, mount points, file system root
  // Drive letters are mapped into the top of a file URI in various ways,
  // depending on the implementation; some applications substitute
  // vertical bar ("|") for the colon after the drive letter, yielding
  // "file:///c|/tmp/test.txt".  In some cases, the colon is left
  // unchanged, as in "file:///c:/tmp/test.txt".  In other cases, the
  // colon is simply omitted, as in "file:///c/tmp/test.txt".
  path = path.replace(/^(.+)\|/, '$1:');

  // for Windows, we need to invert the path separators from what a URI uses
  if (sep == '\\') {
    path = path.replace(/\//g, '\\');
  }

  if (/^.+\:/.test(path)) {
    // has Windows drive at beginning of path
  } else {
    // unix path…
    path = sep + path;
  }

  return host + path;
}

},
"6UGxUZF8AC3LwJ280/cz8J/u6IvLpB+uB0ovcMwycsM=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var types = require('pg-types')

function TypeOverrides(userTypes) {
  this._types = userTypes || types
  this.text = {}
  this.binary = {}
}

TypeOverrides.prototype.getOverrides = function (format) {
  switch (format) {
    case 'text':
      return this.text
    case 'binary':
      return this.binary
    default:
      return {}
  }
}

TypeOverrides.prototype.setTypeParser = function (oid, format, parseFn) {
  if (typeof format === 'function') {
    parseFn = format
    format = 'text'
  }
  this.getOverrides(format)[oid] = parseFn
}

TypeOverrides.prototype.getTypeParser = function (oid, format) {
  format = format || 'text'
  return this.getOverrides(format)[oid] || this._types.getTypeParser(oid, format)
}

module.exports = TypeOverrides

},
"7/q1fgHGlRmV1IMIe6M6pIR1CHQHq3LTxs93+1FFivQ=":
function (require, module, exports, __dirname, __filename) {
'use strict'
const crypto = require('crypto')

function startSession(mechanisms) {
  if (mechanisms.indexOf('SCRAM-SHA-256') === -1) {
    throw new Error('SASL: Only mechanism SCRAM-SHA-256 is currently supported')
  }

  const clientNonce = crypto.randomBytes(18).toString('base64')

  return {
    mechanism: 'SCRAM-SHA-256',
    clientNonce,
    response: 'n,,n=*,r=' + clientNonce,
    message: 'SASLInitialResponse',
  }
}

function continueSession(session, password, serverData) {
  if (session.message !== 'SASLInitialResponse') {
    throw new Error('SASL: Last message was not SASLInitialResponse')
  }

  const sv = extractVariablesFromFirstServerMessage(serverData)

  if (!sv.nonce.startsWith(session.clientNonce)) {
    throw new Error('SASL: SCRAM-SERVER-FIRST-MESSAGE: server nonce does not start with client nonce')
  }

  var saltBytes = Buffer.from(sv.salt, 'base64')

  var saltedPassword = Hi(password, saltBytes, sv.iteration)

  var clientKey = createHMAC(saltedPassword, 'Client Key')
  var storedKey = crypto.createHash('sha256').update(clientKey).digest()

  var clientFirstMessageBare = 'n=*,r=' + session.clientNonce
  var serverFirstMessage = 'r=' + sv.nonce + ',s=' + sv.salt + ',i=' + sv.iteration

  var clientFinalMessageWithoutProof = 'c=biws,r=' + sv.nonce

  var authMessage = clientFirstMessageBare + ',' + serverFirstMessage + ',' + clientFinalMessageWithoutProof

  var clientSignature = createHMAC(storedKey, authMessage)
  var clientProofBytes = xorBuffers(clientKey, clientSignature)
  var clientProof = clientProofBytes.toString('base64')

  var serverKey = createHMAC(saltedPassword, 'Server Key')
  var serverSignatureBytes = createHMAC(serverKey, authMessage)

  session.message = 'SASLResponse'
  session.serverSignature = serverSignatureBytes.toString('base64')
  session.response = clientFinalMessageWithoutProof + ',p=' + clientProof
}

function finalizeSession(session, serverData) {
  if (session.message !== 'SASLResponse') {
    throw new Error('SASL: Last message was not SASLResponse')
  }

  var serverSignature

  String(serverData)
    .split(',')
    .forEach(function (part) {
      switch (part[0]) {
        case 'v':
          serverSignature = part.substr(2)
          break
      }
    })

  if (serverSignature !== session.serverSignature) {
    throw new Error('SASL: SCRAM-SERVER-FINAL-MESSAGE: server signature does not match')
  }
}

function extractVariablesFromFirstServerMessage(data) {
  var nonce, salt, iteration

  String(data)
    .split(',')
    .forEach(function (part) {
      switch (part[0]) {
        case 'r':
          nonce = part.substr(2)
          break
        case 's':
          salt = part.substr(2)
          break
        case 'i':
          iteration = parseInt(part.substr(2), 10)
          break
      }
    })

  if (!nonce) {
    throw new Error('SASL: SCRAM-SERVER-FIRST-MESSAGE: nonce missing')
  }

  if (!salt) {
    throw new Error('SASL: SCRAM-SERVER-FIRST-MESSAGE: salt missing')
  }

  if (!iteration) {
    throw new Error('SASL: SCRAM-SERVER-FIRST-MESSAGE: iteration missing')
  }

  return {
    nonce,
    salt,
    iteration,
  }
}

function xorBuffers(a, b) {
  if (!Buffer.isBuffer(a)) a = Buffer.from(a)
  if (!Buffer.isBuffer(b)) b = Buffer.from(b)
  var res = []
  if (a.length > b.length) {
    for (var i = 0; i < b.length; i++) {
      res.push(a[i] ^ b[i])
    }
  } else {
    for (var j = 0; j < a.length; j++) {
      res.push(a[j] ^ b[j])
    }
  }
  return Buffer.from(res)
}

function createHMAC(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest()
}

function Hi(password, saltBytes, iterations) {
  var ui1 = createHMAC(password, Buffer.concat([saltBytes, Buffer.from([0, 0, 0, 1])]))
  var ui = ui1
  for (var i = 0; i < iterations - 1; i++) {
    ui1 = createHMAC(password, ui1)
    ui = xorBuffers(ui, ui1)
  }

  return ui
}

module.exports = {
  startSession,
  continueSession,
  finalizeSession,
}

},
"70jB4YCHO+f5+2YiT2GmAT0aL9hAWuwRRtNBIqV4sSc=":
function (require, module, exports, __dirname, __filename) {
var Duplex = require('stream').Duplex
var Writable = require('stream').Writable
var util = require('util')

var CopyStream = module.exports = function (pq, options) {
  Duplex.call(this, options)
  this.pq = pq
  this._reading = false
}

util.inherits(CopyStream, Duplex)

// writer methods
CopyStream.prototype._write = function (chunk, encoding, cb) {
  var result = this.pq.putCopyData(chunk)

  // sent successfully
  if (result === 1) return cb()

  // error
  if (result === -1) return cb(new Error(this.pq.errorMessage()))

  // command would block. wait for writable and call again.
  var self = this
  this.pq.writable(function () {
    self._write(chunk, encoding, cb)
  })
}

CopyStream.prototype.end = function () {
  var args = Array.prototype.slice.call(arguments, 0)
  var self = this

  var callback = args.pop()

  if (args.length) {
    this.write(args[0])
  }
  var result = this.pq.putCopyEnd()

  // sent successfully
  if (result === 1) {
    // consume our results and then call 'end' on the
    // "parent" writable class so we can emit 'finish' and
    // all that jazz
    return consumeResults(this.pq, function (err, res) {
      Writable.prototype.end.call(self)

      // handle possible passing of callback to end method
      if (callback) {
        callback(err)
      }
    })
  }

  // error
  if (result === -1) {
    var err = new Error(this.pq.errorMessage())
    return this.emit('error', err)
  }

  // command would block. wait for writable and call end again
  // don't pass any buffers to end on the second call because
  // we already sent them to possible this.write the first time
  // we called end
  return this.pq.writable(function () {
    return self.end.apply(self, callback)
  })
}

// reader methods
CopyStream.prototype._consumeBuffer = function (cb) {
  var result = this.pq.getCopyData(true)
  if (result instanceof Buffer) {
    return setImmediate(function () {
      cb(null, result)
    })
  }
  if (result === -1) {
    // end of stream
    return cb(null, null)
  }
  if (result === 0) {
    var self = this
    this.pq.once('readable', function () {
      self.pq.stopReader()
      self.pq.consumeInput()
      self._consumeBuffer(cb)
    })
    return this.pq.startReader()
  }
  cb(new Error('Unrecognized read status: ' + result))
}

CopyStream.prototype._read = function (size) {
  if (this._reading) return
  this._reading = true
  // console.log('read begin');
  var self = this
  this._consumeBuffer(function (err, buffer) {
    self._reading = false
    if (err) {
      return self.emit('error', err)
    }
    if (buffer === false) {
      // nothing to read for now, return
      return
    }
    self.push(buffer)
  })
}

var consumeResults = function (pq, cb) {
  var cleanup = function () {
    pq.removeListener('readable', onReadable)
    pq.stopReader()
  }

  var readError = function (message) {
    cleanup()
    return cb(new Error(message || pq.errorMessage()))
  }

  var onReadable = function () {
    // read waiting data from the socket
    // e.g. clear the pending 'select'
    if (!pq.consumeInput()) {
      return readError()
    }

    // check if there is still outstanding data
    // if so, wait for it all to come in
    if (pq.isBusy()) {
      return
    }

    // load our result object
    pq.getResult()

    // "read until results return null"
    // or in our case ensure we only have one result
    if (pq.getResult() && pq.resultStatus() !== 'PGRES_COPY_OUT') {
      return readError('Only one result at a time is accepted')
    }

    if (pq.resultStatus() === 'PGRES_FATAL_ERROR') {
      return readError()
    }

    cleanup()
    return cb(null)
  }
  pq.on('readable', onReadable)
  pq.startReader()
}

},
"7ObVSScLpV0IEmsQyZlzJNgI7oKO8A2tI26E5U2dVW0=":
function (require, module, exports, __dirname, __filename) {
var textParsers = require('./lib/textParsers');
var binaryParsers = require('./lib/binaryParsers');
var arrayParser = require('./lib/arrayParser');
var builtinTypes = require('./lib/builtins');

exports.getTypeParser = getTypeParser;
exports.setTypeParser = setTypeParser;
exports.arrayParser = arrayParser;
exports.builtins = builtinTypes;

var typeParsers = {
  text: {},
  binary: {}
};

//the empty parse function
function noParse (val) {
  return String(val);
};

//returns a function used to convert a specific type (specified by
//oid) into a result javascript type
//note: the oid can be obtained via the following sql query:
//SELECT oid FROM pg_type WHERE typname = 'TYPE_NAME_HERE';
function getTypeParser (oid, format) {
  format = format || 'text';
  if (!typeParsers[format]) {
    return noParse;
  }
  return typeParsers[format][oid] || noParse;
};

function setTypeParser (oid, format, parseFn) {
  if(typeof format == 'function') {
    parseFn = format;
    format = 'text';
  }
  typeParsers[format][oid] = parseFn;
};

textParsers.init(function(oid, converter) {
  typeParsers.text[oid] = converter;
});

binaryParsers.init(function(oid, converter) {
  typeParsers.binary[oid] = converter;
});

},
"9QZRF+3tnhRvzr+w/GI0SBAtf/oX1eceqf7y7jLHx2A=":
function (require, module, exports, __dirname, __filename) {
'use strict'

class Result {
  constructor (types, arrayMode) {
    this._types = types
    this._arrayMode = arrayMode

    this.command = undefined
    this.rowCount = undefined
    this.fields = []
    this.rows = []
  }

  consumeCommand (pq) {
    this.command = pq.cmdStatus().split(' ')[0]
    this.rowCount = parseInt(pq.cmdTuples(), 10)
  }

  consumeFields (pq) {
    const nfields = pq.nfields()
    for (var x = 0; x < nfields; x++) {
      this.fields.push({
        name: pq.fname(x),
        dataTypeID: pq.ftype(x)
      })
    }
  }

  consumeRows (pq) {
    const tupleCount = pq.ntuples()
    for (var i = 0; i < tupleCount; i++) {
      const row = this._arrayMode ? this.consumeRowAsArray(pq, i) : this.consumeRowAsObject(pq, i)
      this.rows.push(row)
    }
  }

  consumeRowAsObject (pq, rowIndex) {
    const row = { }
    for (var j = 0; j < this.fields.length; j++) {
      const value = this.readValue(pq, rowIndex, j)
      row[this.fields[j].name] = value
    }
    return row
  }

  consumeRowAsArray (pq, rowIndex) {
    const row = []
    for (var j = 0; j < this.fields.length; j++) {
      const value = this.readValue(pq, rowIndex, j)
      row.push(value)
    }
    return row
  }

  readValue (pq, rowIndex, colIndex) {
    var rawValue = pq.getvalue(rowIndex, colIndex)
    if (rawValue === '') {
      if (pq.getisnull(rowIndex, colIndex)) {
        return null
      }
    }
    const dataTypeId = this.fields[colIndex].dataTypeID
    return this._types.getTypeParser(dataTypeId)(rawValue)
  }
}

function buildResult (pq, types, arrayMode) {
  const result = new Result(types, arrayMode)
  result.consumeCommand(pq)
  result.consumeFields(pq)
  result.consumeRows(pq)

  return result
}

module.exports = buildResult

},
"AkmOfzx4Y8E+OaY4gKD82sH04/2+mzHjhar8XxXRDHA=":
function (require, module, exports, __dirname, __filename) {
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const buffer_writer_1 = require("./buffer-writer");
const writer = new buffer_writer_1.Writer();
const startup = (opts) => {
    // protocol version
    writer.addInt16(3).addInt16(0);
    for (const key of Object.keys(opts)) {
        writer.addCString(key).addCString(opts[key]);
    }
    writer.addCString('client_encoding').addCString('UTF8');
    var bodyBuffer = writer.addCString('').flush();
    // this message is sent without a code
    var length = bodyBuffer.length + 4;
    return new buffer_writer_1.Writer().addInt32(length).add(bodyBuffer).flush();
};
const requestSsl = () => {
    const response = Buffer.allocUnsafe(8);
    response.writeInt32BE(8, 0);
    response.writeInt32BE(80877103, 4);
    return response;
};
const password = (password) => {
    return writer.addCString(password).flush(112 /* startup */);
};
const sendSASLInitialResponseMessage = function (mechanism, initialResponse) {
    // 0x70 = 'p'
    writer.addCString(mechanism).addInt32(Buffer.byteLength(initialResponse)).addString(initialResponse);
    return writer.flush(112 /* startup */);
};
const sendSCRAMClientFinalMessage = function (additionalData) {
    return writer.addString(additionalData).flush(112 /* startup */);
};
const query = (text) => {
    return writer.addCString(text).flush(81 /* query */);
};
const emptyArray = [];
const parse = (query) => {
    // expect something like this:
    // { name: 'queryName',
    //   text: 'select * from blah',
    //   types: ['int8', 'bool'] }
    // normalize missing query names to allow for null
    const name = query.name || '';
    if (name.length > 63) {
        /* eslint-disable no-console */
        console.error('Warning! Postgres only supports 63 characters for query names.');
        console.error('You supplied %s (%s)', name, name.length);
        console.error('This can cause conflicts and silent errors executing queries');
        /* eslint-enable no-console */
    }
    const types = query.types || emptyArray;
    var len = types.length;
    var buffer = writer
        .addCString(name) // name of query
        .addCString(query.text) // actual query text
        .addInt16(len);
    for (var i = 0; i < len; i++) {
        buffer.addInt32(types[i]);
    }
    return writer.flush(80 /* parse */);
};
const bind = (config = {}) => {
    // normalize config
    const portal = config.portal || '';
    const statement = config.statement || '';
    const binary = config.binary || false;
    var values = config.values || emptyArray;
    var len = values.length;
    var useBinary = false;
    // TODO(bmc): all the loops in here aren't nice, we can do better
    for (var j = 0; j < len; j++) {
        useBinary = useBinary || values[j] instanceof Buffer;
    }
    var buffer = writer.addCString(portal).addCString(statement);
    if (!useBinary) {
        buffer.addInt16(0);
    }
    else {
        buffer.addInt16(len);
        for (j = 0; j < len; j++) {
            buffer.addInt16(values[j] instanceof Buffer ? 1 : 0);
        }
    }
    buffer.addInt16(len);
    for (var i = 0; i < len; i++) {
        var val = values[i];
        if (val === null || typeof val === 'undefined') {
            buffer.addInt32(-1);
        }
        else if (val instanceof Buffer) {
            buffer.addInt32(val.length);
            buffer.add(val);
        }
        else {
            buffer.addInt32(Buffer.byteLength(val));
            buffer.addString(val);
        }
    }
    if (binary) {
        buffer.addInt16(1); // format codes to use binary
        buffer.addInt16(1);
    }
    else {
        buffer.addInt16(0); // format codes to use text
    }
    return writer.flush(66 /* bind */);
};
const emptyExecute = Buffer.from([69 /* execute */, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]);
const execute = (config) => {
    // this is the happy path for most queries
    if (!config || (!config.portal && !config.rows)) {
        return emptyExecute;
    }
    const portal = config.portal || '';
    const rows = config.rows || 0;
    const portalLength = Buffer.byteLength(portal);
    const len = 4 + portalLength + 1 + 4;
    // one extra bit for code
    const buff = Buffer.allocUnsafe(1 + len);
    buff[0] = 69 /* execute */;
    buff.writeInt32BE(len, 1);
    buff.write(portal, 5, 'utf-8');
    buff[portalLength + 5] = 0; // null terminate portal cString
    buff.writeUInt32BE(rows, buff.length - 4);
    return buff;
};
const cancel = (processID, secretKey) => {
    const buffer = Buffer.allocUnsafe(16);
    buffer.writeInt32BE(16, 0);
    buffer.writeInt16BE(1234, 4);
    buffer.writeInt16BE(5678, 6);
    buffer.writeInt32BE(processID, 8);
    buffer.writeInt32BE(secretKey, 12);
    return buffer;
};
const cstringMessage = (code, string) => {
    const stringLen = Buffer.byteLength(string);
    const len = 4 + stringLen + 1;
    // one extra bit for code
    const buffer = Buffer.allocUnsafe(1 + len);
    buffer[0] = code;
    buffer.writeInt32BE(len, 1);
    buffer.write(string, 5, 'utf-8');
    buffer[len] = 0; // null terminate cString
    return buffer;
};
const emptyDescribePortal = writer.addCString('P').flush(68 /* describe */);
const emptyDescribeStatement = writer.addCString('S').flush(68 /* describe */);
const describe = (msg) => {
    return msg.name
        ? cstringMessage(68 /* describe */, `${msg.type}${msg.name || ''}`)
        : msg.type === 'P'
            ? emptyDescribePortal
            : emptyDescribeStatement;
};
const close = (msg) => {
    const text = `${msg.type}${msg.name || ''}`;
    return cstringMessage(67 /* close */, text);
};
const copyData = (chunk) => {
    return writer.add(chunk).flush(100 /* copyFromChunk */);
};
const copyFail = (message) => {
    return cstringMessage(102 /* copyFail */, message);
};
const codeOnlyBuffer = (code) => Buffer.from([code, 0x00, 0x00, 0x00, 0x04]);
const flushBuffer = codeOnlyBuffer(72 /* flush */);
const syncBuffer = codeOnlyBuffer(83 /* sync */);
const endBuffer = codeOnlyBuffer(88 /* end */);
const copyDoneBuffer = codeOnlyBuffer(99 /* copyDone */);
const serialize = {
    startup,
    password,
    requestSsl,
    sendSASLInitialResponseMessage,
    sendSCRAMClientFinalMessage,
    query,
    parse,
    bind,
    execute,
    describe,
    close,
    flush: () => flushBuffer,
    sync: () => syncBuffer,
    end: () => endBuffer,
    copyData,
    copyDone: () => copyDoneBuffer,
    copyFail,
    cancel,
};
exports.serialize = serialize;
//# sourceMappingURL=serializer.js.map
},
"CSExl+S0QBLkyDZpqoCIShiekMd33f7x9EyQxBIWc1Q=":
function (require, module, exports, __dirname, __filename) {
/**
 * Following query was used to generate this file:

 SELECT json_object_agg(UPPER(PT.typname), PT.oid::int4 ORDER BY pt.oid)
 FROM pg_type PT
 WHERE typnamespace = (SELECT pgn.oid FROM pg_namespace pgn WHERE nspname = 'pg_catalog') -- Take only builting Postgres types with stable OID (extension types are not guaranted to be stable)
 AND typtype = 'b' -- Only basic types
 AND typelem = 0 -- Ignore aliases
 AND typisdefined -- Ignore undefined types
 */

module.exports = {
    BOOL: 16,
    BYTEA: 17,
    CHAR: 18,
    INT8: 20,
    INT2: 21,
    INT4: 23,
    REGPROC: 24,
    TEXT: 25,
    OID: 26,
    TID: 27,
    XID: 28,
    CID: 29,
    JSON: 114,
    XML: 142,
    PG_NODE_TREE: 194,
    SMGR: 210,
    PATH: 602,
    POLYGON: 604,
    CIDR: 650,
    FLOAT4: 700,
    FLOAT8: 701,
    ABSTIME: 702,
    RELTIME: 703,
    TINTERVAL: 704,
    CIRCLE: 718,
    MACADDR8: 774,
    MONEY: 790,
    MACADDR: 829,
    INET: 869,
    ACLITEM: 1033,
    BPCHAR: 1042,
    VARCHAR: 1043,
    DATE: 1082,
    TIME: 1083,
    TIMESTAMP: 1114,
    TIMESTAMPTZ: 1184,
    INTERVAL: 1186,
    TIMETZ: 1266,
    BIT: 1560,
    VARBIT: 1562,
    NUMERIC: 1700,
    REFCURSOR: 1790,
    REGPROCEDURE: 2202,
    REGOPER: 2203,
    REGOPERATOR: 2204,
    REGCLASS: 2205,
    REGTYPE: 2206,
    UUID: 2950,
    TXID_SNAPSHOT: 2970,
    PG_LSN: 3220,
    PG_NDISTINCT: 3361,
    PG_DEPENDENCIES: 3402,
    TSVECTOR: 3614,
    TSQUERY: 3615,
    GTSVECTOR: 3642,
    REGCONFIG: 3734,
    REGDICTIONARY: 3769,
    JSONB: 3802,
    REGNAMESPACE: 4089,
    REGROLE: 4096
};

},
"DTPuMih+7PorANabFCgekfW6WljofT8j7Ihib2u4LYA=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var EventEmitter = require('events').EventEmitter
var util = require('util')
var utils = require('./utils')
var sasl = require('./sasl')
var pgPass = require('pgpass')
var TypeOverrides = require('./type-overrides')

var ConnectionParameters = require('./connection-parameters')
var Query = require('./query')
var defaults = require('./defaults')
var Connection = require('./connection')

var Client = function (config) {
  EventEmitter.call(this)

  this.connectionParameters = new ConnectionParameters(config)
  this.user = this.connectionParameters.user
  this.database = this.connectionParameters.database
  this.port = this.connectionParameters.port
  this.host = this.connectionParameters.host

  // "hiding" the password so it doesn't show up in stack traces
  // or if the client is console.logged
  Object.defineProperty(this, 'password', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: this.connectionParameters.password,
  })

  this.replication = this.connectionParameters.replication

  var c = config || {}

  this._Promise = c.Promise || global.Promise
  this._types = new TypeOverrides(c.types)
  this._ending = false
  this._connecting = false
  this._connected = false
  this._connectionError = false
  this._queryable = true

  this.connection =
    c.connection ||
    new Connection({
      stream: c.stream,
      ssl: this.connectionParameters.ssl,
      keepAlive: c.keepAlive || false,
      keepAliveInitialDelayMillis: c.keepAliveInitialDelayMillis || 0,
      encoding: this.connectionParameters.client_encoding || 'utf8',
    })
  this.queryQueue = []
  this.binary = c.binary || defaults.binary
  this.processID = null
  this.secretKey = null
  this.ssl = this.connectionParameters.ssl || false
  this._connectionTimeoutMillis = c.connectionTimeoutMillis || 0
}

util.inherits(Client, EventEmitter)

Client.prototype._errorAllQueries = function (err) {
  const enqueueError = (query) => {
    process.nextTick(() => {
      query.handleError(err, this.connection)
    })
  }

  if (this.activeQuery) {
    enqueueError(this.activeQuery)
    this.activeQuery = null
  }

  this.queryQueue.forEach(enqueueError)
  this.queryQueue.length = 0
}

Client.prototype._connect = function (callback) {
  var self = this
  var con = this.connection
  if (this._connecting || this._connected) {
    const err = new Error('Client has already been connected. You cannot reuse a client.')
    process.nextTick(() => {
      callback(err)
    })
    return
  }
  this._connecting = true

  var connectionTimeoutHandle
  if (this._connectionTimeoutMillis > 0) {
    connectionTimeoutHandle = setTimeout(() => {
      con._ending = true
      con.stream.destroy(new Error('timeout expired'))
    }, this._connectionTimeoutMillis)
  }

  if (this.host && this.host.indexOf('/') === 0) {
    con.connect(this.host + '/.s.PGSQL.' + this.port)
  } else {
    con.connect(this.port, this.host)
  }

  // once connection is established send startup message
  con.on('connect', function () {
    if (self.ssl) {
      con.requestSsl()
    } else {
      con.startup(self.getStartupConf())
    }
  })

  con.on('sslconnect', function () {
    con.startup(self.getStartupConf())
  })

  function checkPgPass(cb) {
    return function (msg) {
      if (typeof self.password === 'function') {
        self._Promise
          .resolve()
          .then(() => self.password())
          .then((pass) => {
            if (pass !== undefined) {
              if (typeof pass !== 'string') {
                con.emit('error', new TypeError('Password must be a string'))
                return
              }
              self.connectionParameters.password = self.password = pass
            } else {
              self.connectionParameters.password = self.password = null
            }
            cb(msg)
          })
          .catch((err) => {
            con.emit('error', err)
          })
      } else if (self.password !== null) {
        cb(msg)
      } else {
        pgPass(self.connectionParameters, function (pass) {
          if (undefined !== pass) {
            self.connectionParameters.password = self.password = pass
          }
          cb(msg)
        })
      }
    }
  }

  // password request handling
  con.on(
    'authenticationCleartextPassword',
    checkPgPass(function () {
      con.password(self.password)
    })
  )

  // password request handling
  con.on(
    'authenticationMD5Password',
    checkPgPass(function (msg) {
      con.password(utils.postgresMd5PasswordHash(self.user, self.password, msg.salt))
    })
  )

  // password request handling (SASL)
  var saslSession
  con.on(
    'authenticationSASL',
    checkPgPass(function (msg) {
      saslSession = sasl.startSession(msg.mechanisms)

      con.sendSASLInitialResponseMessage(saslSession.mechanism, saslSession.response)
    })
  )

  // password request handling (SASL)
  con.on('authenticationSASLContinue', function (msg) {
    sasl.continueSession(saslSession, self.password, msg.data)

    con.sendSCRAMClientFinalMessage(saslSession.response)
  })

  // password request handling (SASL)
  con.on('authenticationSASLFinal', function (msg) {
    sasl.finalizeSession(saslSession, msg.data)

    saslSession = null
  })

  con.once('backendKeyData', function (msg) {
    self.processID = msg.processID
    self.secretKey = msg.secretKey
  })

  const connectingErrorHandler = (err) => {
    if (this._connectionError) {
      return
    }
    this._connectionError = true
    clearTimeout(connectionTimeoutHandle)
    if (callback) {
      return callback(err)
    }
    this.emit('error', err)
  }

  const connectedErrorHandler = (err) => {
    this._queryable = false
    this._errorAllQueries(err)
    this.emit('error', err)
  }

  const connectedErrorMessageHandler = (msg) => {
    const activeQuery = this.activeQuery

    if (!activeQuery) {
      connectedErrorHandler(msg)
      return
    }

    this.activeQuery = null
    activeQuery.handleError(msg, con)
  }

  con.on('error', connectingErrorHandler)
  con.on('errorMessage', connectingErrorHandler)

  // hook up query handling events to connection
  // after the connection initially becomes ready for queries
  con.once('readyForQuery', function () {
    self._connecting = false
    self._connected = true
    self._attachListeners(con)
    con.removeListener('error', connectingErrorHandler)
    con.removeListener('errorMessage', connectingErrorHandler)
    con.on('error', connectedErrorHandler)
    con.on('errorMessage', connectedErrorMessageHandler)
    clearTimeout(connectionTimeoutHandle)

    // process possible callback argument to Client#connect
    if (callback) {
      callback(null, self)
      // remove callback for proper error handling
      // after the connect event
      callback = null
    }
    self.emit('connect')
  })

  con.on('readyForQuery', function () {
    var activeQuery = self.activeQuery
    self.activeQuery = null
    self.readyForQuery = true
    if (activeQuery) {
      activeQuery.handleReadyForQuery(con)
    }
    self._pulseQueryQueue()
  })

  con.once('end', () => {
    const error = this._ending ? new Error('Connection terminated') : new Error('Connection terminated unexpectedly')

    clearTimeout(connectionTimeoutHandle)
    this._errorAllQueries(error)

    if (!this._ending) {
      // if the connection is ended without us calling .end()
      // on this client then we have an unexpected disconnection
      // treat this as an error unless we've already emitted an error
      // during connection.
      if (this._connecting && !this._connectionError) {
        if (callback) {
          callback(error)
        } else {
          connectedErrorHandler(error)
        }
      } else if (!this._connectionError) {
        connectedErrorHandler(error)
      }
    }

    process.nextTick(() => {
      this.emit('end')
    })
  })

  con.on('notice', function (msg) {
    self.emit('notice', msg)
  })
}

Client.prototype.connect = function (callback) {
  if (callback) {
    this._connect(callback)
    return
  }

  return new this._Promise((resolve, reject) => {
    this._connect((error) => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

Client.prototype._attachListeners = function (con) {
  const self = this
  // delegate rowDescription to active query
  con.on('rowDescription', function (msg) {
    self.activeQuery.handleRowDescription(msg)
  })

  // delegate dataRow to active query
  con.on('dataRow', function (msg) {
    self.activeQuery.handleDataRow(msg)
  })

  // delegate portalSuspended to active query
  // eslint-disable-next-line no-unused-vars
  con.on('portalSuspended', function (msg) {
    self.activeQuery.handlePortalSuspended(con)
  })

  // delegate emptyQuery to active query
  // eslint-disable-next-line no-unused-vars
  con.on('emptyQuery', function (msg) {
    self.activeQuery.handleEmptyQuery(con)
  })

  // delegate commandComplete to active query
  con.on('commandComplete', function (msg) {
    self.activeQuery.handleCommandComplete(msg, con)
  })

  // if a prepared statement has a name and properly parses
  // we track that its already been executed so we don't parse
  // it again on the same client
  // eslint-disable-next-line no-unused-vars
  con.on('parseComplete', function (msg) {
    if (self.activeQuery.name) {
      con.parsedStatements[self.activeQuery.name] = self.activeQuery.text
    }
  })

  // eslint-disable-next-line no-unused-vars
  con.on('copyInResponse', function (msg) {
    self.activeQuery.handleCopyInResponse(self.connection)
  })

  con.on('copyData', function (msg) {
    self.activeQuery.handleCopyData(msg, self.connection)
  })

  con.on('notification', function (msg) {
    self.emit('notification', msg)
  })
}

Client.prototype.getStartupConf = function () {
  var params = this.connectionParameters

  var data = {
    user: params.user,
    database: params.database,
  }

  var appName = params.application_name || params.fallback_application_name
  if (appName) {
    data.application_name = appName
  }
  if (params.replication) {
    data.replication = '' + params.replication
  }
  if (params.statement_timeout) {
    data.statement_timeout = String(parseInt(params.statement_timeout, 10))
  }
  if (params.idle_in_transaction_session_timeout) {
    data.idle_in_transaction_session_timeout = String(parseInt(params.idle_in_transaction_session_timeout, 10))
  }
  if (params.options) {
    data.options = params.options
  }

  return data
}

Client.prototype.cancel = function (client, query) {
  if (client.activeQuery === query) {
    var con = this.connection

    if (this.host && this.host.indexOf('/') === 0) {
      con.connect(this.host + '/.s.PGSQL.' + this.port)
    } else {
      con.connect(this.port, this.host)
    }

    // once connection is established send cancel message
    con.on('connect', function () {
      con.cancel(client.processID, client.secretKey)
    })
  } else if (client.queryQueue.indexOf(query) !== -1) {
    client.queryQueue.splice(client.queryQueue.indexOf(query), 1)
  }
}

Client.prototype.setTypeParser = function (oid, format, parseFn) {
  return this._types.setTypeParser(oid, format, parseFn)
}

Client.prototype.getTypeParser = function (oid, format) {
  return this._types.getTypeParser(oid, format)
}

// Ported from PostgreSQL 9.2.4 source code in src/interfaces/libpq/fe-exec.c
Client.prototype.escapeIdentifier = function (str) {
  return '"' + str.replace(/"/g, '""') + '"'
}

// Ported from PostgreSQL 9.2.4 source code in src/interfaces/libpq/fe-exec.c
Client.prototype.escapeLiteral = function (str) {
  var hasBackslash = false
  var escaped = "'"

  for (var i = 0; i < str.length; i++) {
    var c = str[i]
    if (c === "'") {
      escaped += c + c
    } else if (c === '\\') {
      escaped += c + c
      hasBackslash = true
    } else {
      escaped += c
    }
  }

  escaped += "'"

  if (hasBackslash === true) {
    escaped = ' E' + escaped
  }

  return escaped
}

Client.prototype._pulseQueryQueue = function () {
  if (this.readyForQuery === true) {
    this.activeQuery = this.queryQueue.shift()
    if (this.activeQuery) {
      this.readyForQuery = false
      this.hasExecuted = true

      const queryError = this.activeQuery.submit(this.connection)
      if (queryError) {
        process.nextTick(() => {
          this.activeQuery.handleError(queryError, this.connection)
          this.readyForQuery = true
          this._pulseQueryQueue()
        })
      }
    } else if (this.hasExecuted) {
      this.activeQuery = null
      this.emit('drain')
    }
  }
}

Client.prototype.query = function (config, values, callback) {
  // can take in strings, config object or query object
  var query
  var result
  var readTimeout
  var readTimeoutTimer
  var queryCallback

  if (config === null || config === undefined) {
    throw new TypeError('Client was passed a null or undefined query')
  } else if (typeof config.submit === 'function') {
    readTimeout = config.query_timeout || this.connectionParameters.query_timeout
    result = query = config
    if (typeof values === 'function') {
      query.callback = query.callback || values
    }
  } else {
    readTimeout = this.connectionParameters.query_timeout
    query = new Query(config, values, callback)
    if (!query.callback) {
      result = new this._Promise((resolve, reject) => {
        query.callback = (err, res) => (err ? reject(err) : resolve(res))
      })
    }
  }

  if (readTimeout) {
    queryCallback = query.callback

    readTimeoutTimer = setTimeout(() => {
      var error = new Error('Query read timeout')

      process.nextTick(() => {
        query.handleError(error, this.connection)
      })

      queryCallback(error)

      // we already returned an error,
      // just do nothing if query completes
      query.callback = () => {}

      // Remove from queue
      var index = this.queryQueue.indexOf(query)
      if (index > -1) {
        this.queryQueue.splice(index, 1)
      }

      this._pulseQueryQueue()
    }, readTimeout)

    query.callback = (err, res) => {
      clearTimeout(readTimeoutTimer)
      queryCallback(err, res)
    }
  }

  if (this.binary && !query.binary) {
    query.binary = true
  }

  if (query._result && !query._result._types) {
    query._result._types = this._types
  }

  if (!this._queryable) {
    process.nextTick(() => {
      query.handleError(new Error('Client has encountered a connection error and is not queryable'), this.connection)
    })
    return result
  }

  if (this._ending) {
    process.nextTick(() => {
      query.handleError(new Error('Client was closed and is not queryable'), this.connection)
    })
    return result
  }

  this.queryQueue.push(query)
  this._pulseQueryQueue()
  return result
}

Client.prototype.end = function (cb) {
  this._ending = true

  // if we have never connected, then end is a noop, callback immediately
  if (!this.connection._connecting) {
    if (cb) {
      cb()
    } else {
      return this._Promise.resolve()
    }
  }

  if (this.activeQuery || !this._queryable) {
    // if we have an active query we need to force a disconnect
    // on the socket - otherwise a hung query could block end forever
    this.connection.stream.destroy()
  } else {
    this.connection.end()
  }

  if (cb) {
    this.connection.once('end', cb)
  } else {
    return new this._Promise((resolve) => {
      this.connection.once('end', resolve)
    })
  }
}

// expose a Query constructor
Client.Query = Query

module.exports = Client

},
"I1xz65sqILWF2s9y63OiY4KrT0k9dUNRFt8poUBizpo=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var net = require('net')
var EventEmitter = require('events').EventEmitter
var util = require('util')

const { parse, serialize } = require('pg-protocol')

// TODO(bmc) support binary mode at some point
var Connection = function (config) {
  EventEmitter.call(this)
  config = config || {}
  this.stream = config.stream || new net.Socket()
  this._keepAlive = config.keepAlive
  this._keepAliveInitialDelayMillis = config.keepAliveInitialDelayMillis
  this.lastBuffer = false
  this.parsedStatements = {}
  this.ssl = config.ssl || false
  this._ending = false
  this._emitMessage = false
  var self = this
  this.on('newListener', function (eventName) {
    if (eventName === 'message') {
      self._emitMessage = true
    }
  })
}

util.inherits(Connection, EventEmitter)

Connection.prototype.connect = function (port, host) {
  var self = this

  this._connecting = true
  this.stream.setNoDelay(true)
  this.stream.connect(port, host)

  this.stream.once('connect', function () {
    if (self._keepAlive) {
      self.stream.setKeepAlive(true, self._keepAliveInitialDelayMillis)
    }
    self.emit('connect')
  })

  const reportStreamError = function (error) {
    // errors about disconnections should be ignored during disconnect
    if (self._ending && (error.code === 'ECONNRESET' || error.code === 'EPIPE')) {
      return
    }
    self.emit('error', error)
  }
  this.stream.on('error', reportStreamError)

  this.stream.on('close', function () {
    self.emit('end')
  })

  if (!this.ssl) {
    return this.attachListeners(this.stream)
  }

  this.stream.once('data', function (buffer) {
    var responseCode = buffer.toString('utf8')
    switch (responseCode) {
      case 'S': // Server supports SSL connections, continue with a secure connection
        break
      case 'N': // Server does not support SSL connections
        self.stream.end()
        return self.emit('error', new Error('The server does not support SSL connections'))
      default:
        // Any other response byte, including 'E' (ErrorResponse) indicating a server error
        self.stream.end()
        return self.emit('error', new Error('There was an error establishing an SSL connection'))
    }
    var tls = require('tls')
    const options = Object.assign(
      {
        socket: self.stream,
      },
      self.ssl
    )
    if (net.isIP(host) === 0) {
      options.servername = host
    }
    self.stream = tls.connect(options)
    self.attachListeners(self.stream)
    self.stream.on('error', reportStreamError)

    self.emit('sslconnect')
  })
}

Connection.prototype.attachListeners = function (stream) {
  stream.on('end', () => {
    this.emit('end')
  })
  parse(stream, (msg) => {
    var eventName = msg.name === 'error' ? 'errorMessage' : msg.name
    if (this._emitMessage) {
      this.emit('message', msg)
    }
    this.emit(eventName, msg)
  })
}

Connection.prototype.requestSsl = function () {
  this.stream.write(serialize.requestSsl())
}

Connection.prototype.startup = function (config) {
  this.stream.write(serialize.startup(config))
}

Connection.prototype.cancel = function (processID, secretKey) {
  this._send(serialize.cancel(processID, secretKey))
}

Connection.prototype.password = function (password) {
  this._send(serialize.password(password))
}

Connection.prototype.sendSASLInitialResponseMessage = function (mechanism, initialResponse) {
  this._send(serialize.sendSASLInitialResponseMessage(mechanism, initialResponse))
}

Connection.prototype.sendSCRAMClientFinalMessage = function (additionalData) {
  this._send(serialize.sendSCRAMClientFinalMessage(additionalData))
}

Connection.prototype._send = function (buffer) {
  if (!this.stream.writable) {
    return false
  }
  return this.stream.write(buffer)
}

Connection.prototype.query = function (text) {
  this._send(serialize.query(text))
}

// send parse message
Connection.prototype.parse = function (query) {
  this._send(serialize.parse(query))
}

// send bind message
// "more" === true to buffer the message until flush() is called
Connection.prototype.bind = function (config) {
  this._send(serialize.bind(config))
}

// send execute message
// "more" === true to buffer the message until flush() is called
Connection.prototype.execute = function (config) {
  this._send(serialize.execute(config))
}

const flushBuffer = serialize.flush()
Connection.prototype.flush = function () {
  if (this.stream.writable) {
    this.stream.write(flushBuffer)
  }
}

const syncBuffer = serialize.sync()
Connection.prototype.sync = function () {
  this._ending = true
  this._send(flushBuffer)
  this._send(syncBuffer)
}

const endBuffer = serialize.end()

Connection.prototype.end = function () {
  // 0x58 = 'X'
  this._ending = true
  if (!this._connecting || !this.stream.writable) {
    this.stream.end()
    return
  }
  return this.stream.write(endBuffer, () => {
    this.stream.end()
  })
}

Connection.prototype.close = function (msg) {
  this._send(serialize.close(msg))
}

Connection.prototype.describe = function (msg) {
  this._send(serialize.describe(msg))
}

Connection.prototype.sendCopyFromChunk = function (chunk) {
  this._send(serialize.copyData(chunk))
}

Connection.prototype.endCopyFrom = function () {
  this._send(serialize.copyDone())
}

Connection.prototype.sendCopyFail = function (msg) {
  this._send(serialize.copyFail(msg))
}

module.exports = Connection

},
"OaXwRLrzssGfkVjQKKSRdOsA0eDbq+rm69mBs1V9X9Q=":
function (require, module, exports, __dirname, __filename) {
// export the class if we are in a Node-like system.
if (typeof module === 'object' && module.exports === exports)
  exports = module.exports = SemVer;

// The debug function is excluded entirely from the minified version.
/* nomin */ var debug;
/* nomin */ if (typeof process === 'object' &&
    /* nomin */ process.env &&
    /* nomin */ process.env.NODE_DEBUG &&
    /* nomin */ /\bsemver\b/i.test(process.env.NODE_DEBUG))
  /* nomin */ debug = function() {
    /* nomin */ var args = Array.prototype.slice.call(arguments, 0);
    /* nomin */ args.unshift('SEMVER');
    /* nomin */ console.log.apply(console, args);
    /* nomin */ };
/* nomin */ else
  /* nomin */ debug = function() {};

// Note: this is the semver.org version of the spec that it implements
// Not necessarily the package version of this code.
exports.SEMVER_SPEC_VERSION = '2.0.0';

var MAX_LENGTH = 256;
var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER || 9007199254740991;

// The actual regexps go on exports.re
var re = exports.re = [];
var src = exports.src = [];
var R = 0;

// The following Regular Expressions can be used for tokenizing,
// validating, and parsing SemVer version strings.

// ## Numeric Identifier
// A single `0`, or a non-zero digit followed by zero or more digits.

var NUMERICIDENTIFIER = R++;
src[NUMERICIDENTIFIER] = '0|[1-9]\\d*';
var NUMERICIDENTIFIERLOOSE = R++;
src[NUMERICIDENTIFIERLOOSE] = '[0-9]+';


// ## Non-numeric Identifier
// Zero or more digits, followed by a letter or hyphen, and then zero or
// more letters, digits, or hyphens.

var NONNUMERICIDENTIFIER = R++;
src[NONNUMERICIDENTIFIER] = '\\d*[a-zA-Z-][a-zA-Z0-9-]*';


// ## Main Version
// Three dot-separated numeric identifiers.

var MAINVERSION = R++;
src[MAINVERSION] = '(' + src[NUMERICIDENTIFIER] + ')\\.' +
                   '(' + src[NUMERICIDENTIFIER] + ')\\.' +
                   '(' + src[NUMERICIDENTIFIER] + ')';

var MAINVERSIONLOOSE = R++;
src[MAINVERSIONLOOSE] = '(' + src[NUMERICIDENTIFIERLOOSE] + ')\\.' +
                        '(' + src[NUMERICIDENTIFIERLOOSE] + ')\\.' +
                        '(' + src[NUMERICIDENTIFIERLOOSE] + ')';

// ## Pre-release Version Identifier
// A numeric identifier, or a non-numeric identifier.

var PRERELEASEIDENTIFIER = R++;
src[PRERELEASEIDENTIFIER] = '(?:' + src[NUMERICIDENTIFIER] +
                            '|' + src[NONNUMERICIDENTIFIER] + ')';

var PRERELEASEIDENTIFIERLOOSE = R++;
src[PRERELEASEIDENTIFIERLOOSE] = '(?:' + src[NUMERICIDENTIFIERLOOSE] +
                                 '|' + src[NONNUMERICIDENTIFIER] + ')';


// ## Pre-release Version
// Hyphen, followed by one or more dot-separated pre-release version
// identifiers.

var PRERELEASE = R++;
src[PRERELEASE] = '(?:-(' + src[PRERELEASEIDENTIFIER] +
                  '(?:\\.' + src[PRERELEASEIDENTIFIER] + ')*))';

var PRERELEASELOOSE = R++;
src[PRERELEASELOOSE] = '(?:-?(' + src[PRERELEASEIDENTIFIERLOOSE] +
                       '(?:\\.' + src[PRERELEASEIDENTIFIERLOOSE] + ')*))';

// ## Build Metadata Identifier
// Any combination of digits, letters, or hyphens.

var BUILDIDENTIFIER = R++;
src[BUILDIDENTIFIER] = '[0-9A-Za-z-]+';

// ## Build Metadata
// Plus sign, followed by one or more period-separated build metadata
// identifiers.

var BUILD = R++;
src[BUILD] = '(?:\\+(' + src[BUILDIDENTIFIER] +
             '(?:\\.' + src[BUILDIDENTIFIER] + ')*))';


// ## Full Version String
// A main version, followed optionally by a pre-release version and
// build metadata.

// Note that the only major, minor, patch, and pre-release sections of
// the version string are capturing groups.  The build metadata is not a
// capturing group, because it should not ever be used in version
// comparison.

var FULL = R++;
var FULLPLAIN = 'v?' + src[MAINVERSION] +
                src[PRERELEASE] + '?' +
                src[BUILD] + '?';

src[FULL] = '^' + FULLPLAIN + '$';

// like full, but allows v1.2.3 and =1.2.3, which people do sometimes.
// also, 1.0.0alpha1 (prerelease without the hyphen) which is pretty
// common in the npm registry.
var LOOSEPLAIN = '[v=\\s]*' + src[MAINVERSIONLOOSE] +
                 src[PRERELEASELOOSE] + '?' +
                 src[BUILD] + '?';

var LOOSE = R++;
src[LOOSE] = '^' + LOOSEPLAIN + '$';

var GTLT = R++;
src[GTLT] = '((?:<|>)?=?)';

// Something like "2.*" or "1.2.x".
// Note that "x.x" is a valid xRange identifer, meaning "any version"
// Only the first item is strictly required.
var XRANGEIDENTIFIERLOOSE = R++;
src[XRANGEIDENTIFIERLOOSE] = src[NUMERICIDENTIFIERLOOSE] + '|x|X|\\*';
var XRANGEIDENTIFIER = R++;
src[XRANGEIDENTIFIER] = src[NUMERICIDENTIFIER] + '|x|X|\\*';

var XRANGEPLAIN = R++;
src[XRANGEPLAIN] = '[v=\\s]*(' + src[XRANGEIDENTIFIER] + ')' +
                   '(?:\\.(' + src[XRANGEIDENTIFIER] + ')' +
                   '(?:\\.(' + src[XRANGEIDENTIFIER] + ')' +
                   '(?:' + src[PRERELEASE] + ')?' +
                   src[BUILD] + '?' +
                   ')?)?';

var XRANGEPLAINLOOSE = R++;
src[XRANGEPLAINLOOSE] = '[v=\\s]*(' + src[XRANGEIDENTIFIERLOOSE] + ')' +
                        '(?:\\.(' + src[XRANGEIDENTIFIERLOOSE] + ')' +
                        '(?:\\.(' + src[XRANGEIDENTIFIERLOOSE] + ')' +
                        '(?:' + src[PRERELEASELOOSE] + ')?' +
                        src[BUILD] + '?' +
                        ')?)?';

var XRANGE = R++;
src[XRANGE] = '^' + src[GTLT] + '\\s*' + src[XRANGEPLAIN] + '$';
var XRANGELOOSE = R++;
src[XRANGELOOSE] = '^' + src[GTLT] + '\\s*' + src[XRANGEPLAINLOOSE] + '$';

// Tilde ranges.
// Meaning is "reasonably at or greater than"
var LONETILDE = R++;
src[LONETILDE] = '(?:~>?)';

var TILDETRIM = R++;
src[TILDETRIM] = '(\\s*)' + src[LONETILDE] + '\\s+';
re[TILDETRIM] = new RegExp(src[TILDETRIM], 'g');
var tildeTrimReplace = '$1~';

var TILDE = R++;
src[TILDE] = '^' + src[LONETILDE] + src[XRANGEPLAIN] + '$';
var TILDELOOSE = R++;
src[TILDELOOSE] = '^' + src[LONETILDE] + src[XRANGEPLAINLOOSE] + '$';

// Caret ranges.
// Meaning is "at least and backwards compatible with"
var LONECARET = R++;
src[LONECARET] = '(?:\\^)';

var CARETTRIM = R++;
src[CARETTRIM] = '(\\s*)' + src[LONECARET] + '\\s+';
re[CARETTRIM] = new RegExp(src[CARETTRIM], 'g');
var caretTrimReplace = '$1^';

var CARET = R++;
src[CARET] = '^' + src[LONECARET] + src[XRANGEPLAIN] + '$';
var CARETLOOSE = R++;
src[CARETLOOSE] = '^' + src[LONECARET] + src[XRANGEPLAINLOOSE] + '$';

// A simple gt/lt/eq thing, or just "" to indicate "any version"
var COMPARATORLOOSE = R++;
src[COMPARATORLOOSE] = '^' + src[GTLT] + '\\s*(' + LOOSEPLAIN + ')$|^$';
var COMPARATOR = R++;
src[COMPARATOR] = '^' + src[GTLT] + '\\s*(' + FULLPLAIN + ')$|^$';


// An expression to strip any whitespace between the gtlt and the thing
// it modifies, so that `> 1.2.3` ==> `>1.2.3`
var COMPARATORTRIM = R++;
src[COMPARATORTRIM] = '(\\s*)' + src[GTLT] +
                      '\\s*(' + LOOSEPLAIN + '|' + src[XRANGEPLAIN] + ')';

// this one has to use the /g flag
re[COMPARATORTRIM] = new RegExp(src[COMPARATORTRIM], 'g');
var comparatorTrimReplace = '$1$2$3';


// Something like `1.2.3 - 1.2.4`
// Note that these all use the loose form, because they'll be
// checked against either the strict or loose comparator form
// later.
var HYPHENRANGE = R++;
src[HYPHENRANGE] = '^\\s*(' + src[XRANGEPLAIN] + ')' +
                   '\\s+-\\s+' +
                   '(' + src[XRANGEPLAIN] + ')' +
                   '\\s*$';

var HYPHENRANGELOOSE = R++;
src[HYPHENRANGELOOSE] = '^\\s*(' + src[XRANGEPLAINLOOSE] + ')' +
                        '\\s+-\\s+' +
                        '(' + src[XRANGEPLAINLOOSE] + ')' +
                        '\\s*$';

// Star ranges basically just allow anything at all.
var STAR = R++;
src[STAR] = '(<|>)?=?\\s*\\*';

// Compile to actual regexp objects.
// All are flag-free, unless they were created above with a flag.
for (var i = 0; i < R; i++) {
  debug(i, src[i]);
  if (!re[i])
    re[i] = new RegExp(src[i]);
}

exports.parse = parse;
function parse(version, loose) {
  if (version.length > MAX_LENGTH)
    return null;

  var r = loose ? re[LOOSE] : re[FULL];
  if (!r.test(version))
    return null;

  try {
    return new SemVer(version, loose);
  } catch (er) {
    return null;
  }
}

exports.valid = valid;
function valid(version, loose) {
  var v = parse(version, loose);
  return v ? v.version : null;
}


exports.clean = clean;
function clean(version, loose) {
  var s = parse(version.trim().replace(/^[=v]+/, ''), loose);
  return s ? s.version : null;
}

exports.SemVer = SemVer;

function SemVer(version, loose) {
  if (version instanceof SemVer) {
    if (version.loose === loose)
      return version;
    else
      version = version.version;
  } else if (typeof version !== 'string') {
    throw new TypeError('Invalid Version: ' + version);
  }

  if (version.length > MAX_LENGTH)
    throw new TypeError('version is longer than ' + MAX_LENGTH + ' characters')

  if (!(this instanceof SemVer))
    return new SemVer(version, loose);

  debug('SemVer', version, loose);
  this.loose = loose;
  var m = version.trim().match(loose ? re[LOOSE] : re[FULL]);

  if (!m)
    throw new TypeError('Invalid Version: ' + version);

  this.raw = version;

  // these are actually numbers
  this.major = +m[1];
  this.minor = +m[2];
  this.patch = +m[3];

  if (this.major > MAX_SAFE_INTEGER || this.major < 0)
    throw new TypeError('Invalid major version')

  if (this.minor > MAX_SAFE_INTEGER || this.minor < 0)
    throw new TypeError('Invalid minor version')

  if (this.patch > MAX_SAFE_INTEGER || this.patch < 0)
    throw new TypeError('Invalid patch version')

  // numberify any prerelease numeric ids
  if (!m[4])
    this.prerelease = [];
  else
    this.prerelease = m[4].split('.').map(function(id) {
      return (/^[0-9]+$/.test(id)) ? +id : id;
    });

  this.build = m[5] ? m[5].split('.') : [];
  this.format();
}

SemVer.prototype.format = function() {
  this.version = this.major + '.' + this.minor + '.' + this.patch;
  if (this.prerelease.length)
    this.version += '-' + this.prerelease.join('.');
  return this.version;
};

SemVer.prototype.inspect = function() {
  return '<SemVer "' + this + '">';
};

SemVer.prototype.toString = function() {
  return this.version;
};

SemVer.prototype.compare = function(other) {
  debug('SemVer.compare', this.version, this.loose, other);
  if (!(other instanceof SemVer))
    other = new SemVer(other, this.loose);

  return this.compareMain(other) || this.comparePre(other);
};

SemVer.prototype.compareMain = function(other) {
  if (!(other instanceof SemVer))
    other = new SemVer(other, this.loose);

  return compareIdentifiers(this.major, other.major) ||
         compareIdentifiers(this.minor, other.minor) ||
         compareIdentifiers(this.patch, other.patch);
};

SemVer.prototype.comparePre = function(other) {
  if (!(other instanceof SemVer))
    other = new SemVer(other, this.loose);

  // NOT having a prerelease is > having one
  if (this.prerelease.length && !other.prerelease.length)
    return -1;
  else if (!this.prerelease.length && other.prerelease.length)
    return 1;
  else if (!this.prerelease.length && !other.prerelease.length)
    return 0;

  var i = 0;
  do {
    var a = this.prerelease[i];
    var b = other.prerelease[i];
    debug('prerelease compare', i, a, b);
    if (a === undefined && b === undefined)
      return 0;
    else if (b === undefined)
      return 1;
    else if (a === undefined)
      return -1;
    else if (a === b)
      continue;
    else
      return compareIdentifiers(a, b);
  } while (++i);
};

// preminor will bump the version up to the next minor release, and immediately
// down to pre-release. premajor and prepatch work the same way.
SemVer.prototype.inc = function(release, identifier) {
  switch (release) {
    case 'premajor':
      this.prerelease.length = 0;
      this.patch = 0;
      this.minor = 0;
      this.major++;
      this.inc('pre', identifier);
      break;
    case 'preminor':
      this.prerelease.length = 0;
      this.patch = 0;
      this.minor++;
      this.inc('pre', identifier);
      break;
    case 'prepatch':
      // If this is already a prerelease, it will bump to the next version
      // drop any prereleases that might already exist, since they are not
      // relevant at this point.
      this.prerelease.length = 0;
      this.inc('patch', identifier);
      this.inc('pre', identifier);
      break;
    // If the input is a non-prerelease version, this acts the same as
    // prepatch.
    case 'prerelease':
      if (this.prerelease.length === 0)
        this.inc('patch', identifier);
      this.inc('pre', identifier);
      break;

    case 'major':
      // If this is a pre-major version, bump up to the same major version.
      // Otherwise increment major.
      // 1.0.0-5 bumps to 1.0.0
      // 1.1.0 bumps to 2.0.0
      if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0)
        this.major++;
      this.minor = 0;
      this.patch = 0;
      this.prerelease = [];
      break;
    case 'minor':
      // If this is a pre-minor version, bump up to the same minor version.
      // Otherwise increment minor.
      // 1.2.0-5 bumps to 1.2.0
      // 1.2.1 bumps to 1.3.0
      if (this.patch !== 0 || this.prerelease.length === 0)
        this.minor++;
      this.patch = 0;
      this.prerelease = [];
      break;
    case 'patch':
      // If this is not a pre-release version, it will increment the patch.
      // If it is a pre-release it will bump up to the same patch version.
      // 1.2.0-5 patches to 1.2.0
      // 1.2.0 patches to 1.2.1
      if (this.prerelease.length === 0)
        this.patch++;
      this.prerelease = [];
      break;
    // This probably shouldn't be used publicly.
    // 1.0.0 "pre" would become 1.0.0-0 which is the wrong direction.
    case 'pre':
      if (this.prerelease.length === 0)
        this.prerelease = [0];
      else {
        var i = this.prerelease.length;
        while (--i >= 0) {
          if (typeof this.prerelease[i] === 'number') {
            this.prerelease[i]++;
            i = -2;
          }
        }
        if (i === -1) // didn't increment anything
          this.prerelease.push(0);
      }
      if (identifier) {
        // 1.2.0-beta.1 bumps to 1.2.0-beta.2,
        // 1.2.0-beta.fooblz or 1.2.0-beta bumps to 1.2.0-beta.0
        if (this.prerelease[0] === identifier) {
          if (isNaN(this.prerelease[1]))
            this.prerelease = [identifier, 0];
        } else
          this.prerelease = [identifier, 0];
      }
      break;

    default:
      throw new Error('invalid increment argument: ' + release);
  }
  this.format();
  return this;
};

exports.inc = inc;
function inc(version, release, loose, identifier) {
  if (typeof(loose) === 'string') {
    identifier = loose;
    loose = undefined;
  }

  try {
    return new SemVer(version, loose).inc(release, identifier).version;
  } catch (er) {
    return null;
  }
}

exports.diff = diff;
function diff(version1, version2) {
  if (eq(version1, version2)) {
    return null;
  } else {
    var v1 = parse(version1);
    var v2 = parse(version2);
    if (v1.prerelease.length || v2.prerelease.length) {
      for (var key in v1) {
        if (key === 'major' || key === 'minor' || key === 'patch') {
          if (v1[key] !== v2[key]) {
            return 'pre'+key;
          }
        }
      }
      return 'prerelease';
    }
    for (var key in v1) {
      if (key === 'major' || key === 'minor' || key === 'patch') {
        if (v1[key] !== v2[key]) {
          return key;
        }
      }
    }
  }
}

exports.compareIdentifiers = compareIdentifiers;

var numeric = /^[0-9]+$/;
function compareIdentifiers(a, b) {
  var anum = numeric.test(a);
  var bnum = numeric.test(b);

  if (anum && bnum) {
    a = +a;
    b = +b;
  }

  return (anum && !bnum) ? -1 :
         (bnum && !anum) ? 1 :
         a < b ? -1 :
         a > b ? 1 :
         0;
}

exports.rcompareIdentifiers = rcompareIdentifiers;
function rcompareIdentifiers(a, b) {
  return compareIdentifiers(b, a);
}

exports.major = major;
function major(a, loose) {
  return new SemVer(a, loose).major;
}

exports.minor = minor;
function minor(a, loose) {
  return new SemVer(a, loose).minor;
}

exports.patch = patch;
function patch(a, loose) {
  return new SemVer(a, loose).patch;
}

exports.compare = compare;
function compare(a, b, loose) {
  return new SemVer(a, loose).compare(b);
}

exports.compareLoose = compareLoose;
function compareLoose(a, b) {
  return compare(a, b, true);
}

exports.rcompare = rcompare;
function rcompare(a, b, loose) {
  return compare(b, a, loose);
}

exports.sort = sort;
function sort(list, loose) {
  return list.sort(function(a, b) {
    return exports.compare(a, b, loose);
  });
}

exports.rsort = rsort;
function rsort(list, loose) {
  return list.sort(function(a, b) {
    return exports.rcompare(a, b, loose);
  });
}

exports.gt = gt;
function gt(a, b, loose) {
  return compare(a, b, loose) > 0;
}

exports.lt = lt;
function lt(a, b, loose) {
  return compare(a, b, loose) < 0;
}

exports.eq = eq;
function eq(a, b, loose) {
  return compare(a, b, loose) === 0;
}

exports.neq = neq;
function neq(a, b, loose) {
  return compare(a, b, loose) !== 0;
}

exports.gte = gte;
function gte(a, b, loose) {
  return compare(a, b, loose) >= 0;
}

exports.lte = lte;
function lte(a, b, loose) {
  return compare(a, b, loose) <= 0;
}

exports.cmp = cmp;
function cmp(a, op, b, loose) {
  var ret;
  switch (op) {
    case '===':
      if (typeof a === 'object') a = a.version;
      if (typeof b === 'object') b = b.version;
      ret = a === b;
      break;
    case '!==':
      if (typeof a === 'object') a = a.version;
      if (typeof b === 'object') b = b.version;
      ret = a !== b;
      break;
    case '': case '=': case '==': ret = eq(a, b, loose); break;
    case '!=': ret = neq(a, b, loose); break;
    case '>': ret = gt(a, b, loose); break;
    case '>=': ret = gte(a, b, loose); break;
    case '<': ret = lt(a, b, loose); break;
    case '<=': ret = lte(a, b, loose); break;
    default: throw new TypeError('Invalid operator: ' + op);
  }
  return ret;
}

exports.Comparator = Comparator;
function Comparator(comp, loose) {
  if (comp instanceof Comparator) {
    if (comp.loose === loose)
      return comp;
    else
      comp = comp.value;
  }

  if (!(this instanceof Comparator))
    return new Comparator(comp, loose);

  debug('comparator', comp, loose);
  this.loose = loose;
  this.parse(comp);

  if (this.semver === ANY)
    this.value = '';
  else
    this.value = this.operator + this.semver.version;

  debug('comp', this);
}

var ANY = {};
Comparator.prototype.parse = function(comp) {
  var r = this.loose ? re[COMPARATORLOOSE] : re[COMPARATOR];
  var m = comp.match(r);

  if (!m)
    throw new TypeError('Invalid comparator: ' + comp);

  this.operator = m[1];
  if (this.operator === '=')
    this.operator = '';

  // if it literally is just '>' or '' then allow anything.
  if (!m[2])
    this.semver = ANY;
  else
    this.semver = new SemVer(m[2], this.loose);
};

Comparator.prototype.inspect = function() {
  return '<SemVer Comparator "' + this + '">';
};

Comparator.prototype.toString = function() {
  return this.value;
};

Comparator.prototype.test = function(version) {
  debug('Comparator.test', version, this.loose);

  if (this.semver === ANY)
    return true;

  if (typeof version === 'string')
    version = new SemVer(version, this.loose);

  return cmp(version, this.operator, this.semver, this.loose);
};


exports.Range = Range;
function Range(range, loose) {
  if ((range instanceof Range) && range.loose === loose)
    return range;

  if (!(this instanceof Range))
    return new Range(range, loose);

  this.loose = loose;

  // First, split based on boolean or ||
  this.raw = range;
  this.set = range.split(/\s*\|\|\s*/).map(function(range) {
    return this.parseRange(range.trim());
  }, this).filter(function(c) {
    // throw out any that are not relevant for whatever reason
    return c.length;
  });

  if (!this.set.length) {
    throw new TypeError('Invalid SemVer Range: ' + range);
  }

  this.format();
}

Range.prototype.inspect = function() {
  return '<SemVer Range "' + this.range + '">';
};

Range.prototype.format = function() {
  this.range = this.set.map(function(comps) {
    return comps.join(' ').trim();
  }).join('||').trim();
  return this.range;
};

Range.prototype.toString = function() {
  return this.range;
};

Range.prototype.parseRange = function(range) {
  var loose = this.loose;
  range = range.trim();
  debug('range', range, loose);
  // `1.2.3 - 1.2.4` => `>=1.2.3 <=1.2.4`
  var hr = loose ? re[HYPHENRANGELOOSE] : re[HYPHENRANGE];
  range = range.replace(hr, hyphenReplace);
  debug('hyphen replace', range);
  // `> 1.2.3 < 1.2.5` => `>1.2.3 <1.2.5`
  range = range.replace(re[COMPARATORTRIM], comparatorTrimReplace);
  debug('comparator trim', range, re[COMPARATORTRIM]);

  // `~ 1.2.3` => `~1.2.3`
  range = range.replace(re[TILDETRIM], tildeTrimReplace);

  // `^ 1.2.3` => `^1.2.3`
  range = range.replace(re[CARETTRIM], caretTrimReplace);

  // normalize spaces
  range = range.split(/\s+/).join(' ');

  // At this point, the range is completely trimmed and
  // ready to be split into comparators.

  var compRe = loose ? re[COMPARATORLOOSE] : re[COMPARATOR];
  var set = range.split(' ').map(function(comp) {
    return parseComparator(comp, loose);
  }).join(' ').split(/\s+/);
  if (this.loose) {
    // in loose mode, throw out any that are not valid comparators
    set = set.filter(function(comp) {
      return !!comp.match(compRe);
    });
  }
  set = set.map(function(comp) {
    return new Comparator(comp, loose);
  });

  return set;
};

// Mostly just for testing and legacy API reasons
exports.toComparators = toComparators;
function toComparators(range, loose) {
  return new Range(range, loose).set.map(function(comp) {
    return comp.map(function(c) {
      return c.value;
    }).join(' ').trim().split(' ');
  });
}

// comprised of xranges, tildes, stars, and gtlt's at this point.
// already replaced the hyphen ranges
// turn into a set of JUST comparators.
function parseComparator(comp, loose) {
  debug('comp', comp);
  comp = replaceCarets(comp, loose);
  debug('caret', comp);
  comp = replaceTildes(comp, loose);
  debug('tildes', comp);
  comp = replaceXRanges(comp, loose);
  debug('xrange', comp);
  comp = replaceStars(comp, loose);
  debug('stars', comp);
  return comp;
}

function isX(id) {
  return !id || id.toLowerCase() === 'x' || id === '*';
}

// ~, ~> --> * (any, kinda silly)
// ~2, ~2.x, ~2.x.x, ~>2, ~>2.x ~>2.x.x --> >=2.0.0 <3.0.0
// ~2.0, ~2.0.x, ~>2.0, ~>2.0.x --> >=2.0.0 <2.1.0
// ~1.2, ~1.2.x, ~>1.2, ~>1.2.x --> >=1.2.0 <1.3.0
// ~1.2.3, ~>1.2.3 --> >=1.2.3 <1.3.0
// ~1.2.0, ~>1.2.0 --> >=1.2.0 <1.3.0
function replaceTildes(comp, loose) {
  return comp.trim().split(/\s+/).map(function(comp) {
    return replaceTilde(comp, loose);
  }).join(' ');
}

function replaceTilde(comp, loose) {
  var r = loose ? re[TILDELOOSE] : re[TILDE];
  return comp.replace(r, function(_, M, m, p, pr) {
    debug('tilde', comp, _, M, m, p, pr);
    var ret;

    if (isX(M))
      ret = '';
    else if (isX(m))
      ret = '>=' + M + '.0.0 <' + (+M + 1) + '.0.0';
    else if (isX(p))
      // ~1.2 == >=1.2.0- <1.3.0-
      ret = '>=' + M + '.' + m + '.0 <' + M + '.' + (+m + 1) + '.0';
    else if (pr) {
      debug('replaceTilde pr', pr);
      if (pr.charAt(0) !== '-')
        pr = '-' + pr;
      ret = '>=' + M + '.' + m + '.' + p + pr +
            ' <' + M + '.' + (+m + 1) + '.0';
    } else
      // ~1.2.3 == >=1.2.3 <1.3.0
      ret = '>=' + M + '.' + m + '.' + p +
            ' <' + M + '.' + (+m + 1) + '.0';

    debug('tilde return', ret);
    return ret;
  });
}

// ^ --> * (any, kinda silly)
// ^2, ^2.x, ^2.x.x --> >=2.0.0 <3.0.0
// ^2.0, ^2.0.x --> >=2.0.0 <3.0.0
// ^1.2, ^1.2.x --> >=1.2.0 <2.0.0
// ^1.2.3 --> >=1.2.3 <2.0.0
// ^1.2.0 --> >=1.2.0 <2.0.0
function replaceCarets(comp, loose) {
  return comp.trim().split(/\s+/).map(function(comp) {
    return replaceCaret(comp, loose);
  }).join(' ');
}

function replaceCaret(comp, loose) {
  debug('caret', comp, loose);
  var r = loose ? re[CARETLOOSE] : re[CARET];
  return comp.replace(r, function(_, M, m, p, pr) {
    debug('caret', comp, _, M, m, p, pr);
    var ret;

    if (isX(M))
      ret = '';
    else if (isX(m))
      ret = '>=' + M + '.0.0 <' + (+M + 1) + '.0.0';
    else if (isX(p)) {
      if (M === '0')
        ret = '>=' + M + '.' + m + '.0 <' + M + '.' + (+m + 1) + '.0';
      else
        ret = '>=' + M + '.' + m + '.0 <' + (+M + 1) + '.0.0';
    } else if (pr) {
      debug('replaceCaret pr', pr);
      if (pr.charAt(0) !== '-')
        pr = '-' + pr;
      if (M === '0') {
        if (m === '0')
          ret = '>=' + M + '.' + m + '.' + p + pr +
                ' <' + M + '.' + m + '.' + (+p + 1);
        else
          ret = '>=' + M + '.' + m + '.' + p + pr +
                ' <' + M + '.' + (+m + 1) + '.0';
      } else
        ret = '>=' + M + '.' + m + '.' + p + pr +
              ' <' + (+M + 1) + '.0.0';
    } else {
      debug('no pr');
      if (M === '0') {
        if (m === '0')
          ret = '>=' + M + '.' + m + '.' + p +
                ' <' + M + '.' + m + '.' + (+p + 1);
        else
          ret = '>=' + M + '.' + m + '.' + p +
                ' <' + M + '.' + (+m + 1) + '.0';
      } else
        ret = '>=' + M + '.' + m + '.' + p +
              ' <' + (+M + 1) + '.0.0';
    }

    debug('caret return', ret);
    return ret;
  });
}

function replaceXRanges(comp, loose) {
  debug('replaceXRanges', comp, loose);
  return comp.split(/\s+/).map(function(comp) {
    return replaceXRange(comp, loose);
  }).join(' ');
}

function replaceXRange(comp, loose) {
  comp = comp.trim();
  var r = loose ? re[XRANGELOOSE] : re[XRANGE];
  return comp.replace(r, function(ret, gtlt, M, m, p, pr) {
    debug('xRange', comp, ret, gtlt, M, m, p, pr);
    var xM = isX(M);
    var xm = xM || isX(m);
    var xp = xm || isX(p);
    var anyX = xp;

    if (gtlt === '=' && anyX)
      gtlt = '';

    if (xM) {
      if (gtlt === '>' || gtlt === '<') {
        // nothing is allowed
        ret = '<0.0.0';
      } else {
        // nothing is forbidden
        ret = '*';
      }
    } else if (gtlt && anyX) {
      // replace X with 0
      if (xm)
        m = 0;
      if (xp)
        p = 0;

      if (gtlt === '>') {
        // >1 => >=2.0.0
        // >1.2 => >=1.3.0
        // >1.2.3 => >= 1.2.4
        gtlt = '>=';
        if (xm) {
          M = +M + 1;
          m = 0;
          p = 0;
        } else if (xp) {
          m = +m + 1;
          p = 0;
        }
      } else if (gtlt === '<=') {
        // <=0.7.x is actually <0.8.0, since any 0.7.x should
        // pass.  Similarly, <=7.x is actually <8.0.0, etc.
        gtlt = '<'
        if (xm)
          M = +M + 1
        else
          m = +m + 1
      }

      ret = gtlt + M + '.' + m + '.' + p;
    } else if (xm) {
      ret = '>=' + M + '.0.0 <' + (+M + 1) + '.0.0';
    } else if (xp) {
      ret = '>=' + M + '.' + m + '.0 <' + M + '.' + (+m + 1) + '.0';
    }

    debug('xRange return', ret);

    return ret;
  });
}

// Because * is AND-ed with everything else in the comparator,
// and '' means "any version", just remove the *s entirely.
function replaceStars(comp, loose) {
  debug('replaceStars', comp, loose);
  // Looseness is ignored here.  star is always as loose as it gets!
  return comp.trim().replace(re[STAR], '');
}

// This function is passed to string.replace(re[HYPHENRANGE])
// M, m, patch, prerelease, build
// 1.2 - 3.4.5 => >=1.2.0 <=3.4.5
// 1.2.3 - 3.4 => >=1.2.0 <3.5.0 Any 3.4.x will do
// 1.2 - 3.4 => >=1.2.0 <3.5.0
function hyphenReplace($0,
                       from, fM, fm, fp, fpr, fb,
                       to, tM, tm, tp, tpr, tb) {

  if (isX(fM))
    from = '';
  else if (isX(fm))
    from = '>=' + fM + '.0.0';
  else if (isX(fp))
    from = '>=' + fM + '.' + fm + '.0';
  else
    from = '>=' + from;

  if (isX(tM))
    to = '';
  else if (isX(tm))
    to = '<' + (+tM + 1) + '.0.0';
  else if (isX(tp))
    to = '<' + tM + '.' + (+tm + 1) + '.0';
  else if (tpr)
    to = '<=' + tM + '.' + tm + '.' + tp + '-' + tpr;
  else
    to = '<=' + to;

  return (from + ' ' + to).trim();
}


// if ANY of the sets match ALL of its comparators, then pass
Range.prototype.test = function(version) {
  if (!version)
    return false;

  if (typeof version === 'string')
    version = new SemVer(version, this.loose);

  for (var i = 0; i < this.set.length; i++) {
    if (testSet(this.set[i], version))
      return true;
  }
  return false;
};

function testSet(set, version) {
  for (var i = 0; i < set.length; i++) {
    if (!set[i].test(version))
      return false;
  }

  if (version.prerelease.length) {
    // Find the set of versions that are allowed to have prereleases
    // For example, ^1.2.3-pr.1 desugars to >=1.2.3-pr.1 <2.0.0
    // That should allow `1.2.3-pr.2` to pass.
    // However, `1.2.4-alpha.notready` should NOT be allowed,
    // even though it's within the range set by the comparators.
    for (var i = 0; i < set.length; i++) {
      debug(set[i].semver);
      if (set[i].semver === ANY)
        return true;

      if (set[i].semver.prerelease.length > 0) {
        var allowed = set[i].semver;
        if (allowed.major === version.major &&
            allowed.minor === version.minor &&
            allowed.patch === version.patch)
          return true;
      }
    }

    // Version has a -pre, but it's not one of the ones we like.
    return false;
  }

  return true;
}

exports.satisfies = satisfies;
function satisfies(version, range, loose) {
  try {
    range = new Range(range, loose);
  } catch (er) {
    return false;
  }
  return range.test(version);
}

exports.maxSatisfying = maxSatisfying;
function maxSatisfying(versions, range, loose) {
  return versions.filter(function(version) {
    return satisfies(version, range, loose);
  }).sort(function(a, b) {
    return rcompare(a, b, loose);
  })[0] || null;
}

exports.validRange = validRange;
function validRange(range, loose) {
  try {
    // Return '*' instead of '' so that truthiness works.
    // This will throw if it's invalid anyway
    return new Range(range, loose).range || '*';
  } catch (er) {
    return null;
  }
}

// Determine if version is less than all the versions possible in the range
exports.ltr = ltr;
function ltr(version, range, loose) {
  return outside(version, range, '<', loose);
}

// Determine if version is greater than all the versions possible in the range.
exports.gtr = gtr;
function gtr(version, range, loose) {
  return outside(version, range, '>', loose);
}

exports.outside = outside;
function outside(version, range, hilo, loose) {
  version = new SemVer(version, loose);
  range = new Range(range, loose);

  var gtfn, ltefn, ltfn, comp, ecomp;
  switch (hilo) {
    case '>':
      gtfn = gt;
      ltefn = lte;
      ltfn = lt;
      comp = '>';
      ecomp = '>=';
      break;
    case '<':
      gtfn = lt;
      ltefn = gte;
      ltfn = gt;
      comp = '<';
      ecomp = '<=';
      break;
    default:
      throw new TypeError('Must provide a hilo val of "<" or ">"');
  }

  // If it satisifes the range it is not outside
  if (satisfies(version, range, loose)) {
    return false;
  }

  // From now on, variable terms are as if we're in "gtr" mode.
  // but note that everything is flipped for the "ltr" function.

  for (var i = 0; i < range.set.length; ++i) {
    var comparators = range.set[i];

    var high = null;
    var low = null;

    comparators.forEach(function(comparator) {
      high = high || comparator;
      low = low || comparator;
      if (gtfn(comparator.semver, high.semver, loose)) {
        high = comparator;
      } else if (ltfn(comparator.semver, low.semver, loose)) {
        low = comparator;
      }
    });

    // If the edge version comparator has a operator then our version
    // isn't outside it
    if (high.operator === comp || high.operator === ecomp) {
      return false;
    }

    // If the lowest version comparator has an operator and our version
    // is less than it then it isn't higher than the range
    if ((!low.operator || low.operator === comp) &&
        ltefn(version, low.semver)) {
      return false;
    } else if (low.operator === ecomp && ltfn(version, low.semver)) {
      return false;
    }
  }
  return true;
}

// Use the define() function if we're in AMD land
if (typeof define === 'function' && define.amd)
  define(exports);

},
"OpYE+gjRDHgWmbmbYMiYBFbrNQ1rtpSOdapBN5V5QCI=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var EventEmitter = require('events').EventEmitter
var util = require('util')
var utils = require('../utils')

var NativeQuery = (module.exports = function (config, values, callback) {
  EventEmitter.call(this)
  config = utils.normalizeQueryConfig(config, values, callback)
  this.text = config.text
  this.values = config.values
  this.name = config.name
  this.callback = config.callback
  this.state = 'new'
  this._arrayMode = config.rowMode === 'array'

  // if the 'row' event is listened for
  // then emit them as they come in
  // without setting singleRowMode to true
  // this has almost no meaning because libpq
  // reads all rows into memory befor returning any
  this._emitRowEvents = false
  this.on(
    'newListener',
    function (event) {
      if (event === 'row') this._emitRowEvents = true
    }.bind(this)
  )
})

util.inherits(NativeQuery, EventEmitter)

var errorFieldMap = {
  /* eslint-disable quote-props */
  sqlState: 'code',
  statementPosition: 'position',
  messagePrimary: 'message',
  context: 'where',
  schemaName: 'schema',
  tableName: 'table',
  columnName: 'column',
  dataTypeName: 'dataType',
  constraintName: 'constraint',
  sourceFile: 'file',
  sourceLine: 'line',
  sourceFunction: 'routine',
}

NativeQuery.prototype.handleError = function (err) {
  // copy pq error fields into the error object
  var fields = this.native.pq.resultErrorFields()
  if (fields) {
    for (var key in fields) {
      var normalizedFieldName = errorFieldMap[key] || key
      err[normalizedFieldName] = fields[key]
    }
  }
  if (this.callback) {
    this.callback(err)
  } else {
    this.emit('error', err)
  }
  this.state = 'error'
}

NativeQuery.prototype.then = function (onSuccess, onFailure) {
  return this._getPromise().then(onSuccess, onFailure)
}

NativeQuery.prototype.catch = function (callback) {
  return this._getPromise().catch(callback)
}

NativeQuery.prototype._getPromise = function () {
  if (this._promise) return this._promise
  this._promise = new Promise(
    function (resolve, reject) {
      this._once('end', resolve)
      this._once('error', reject)
    }.bind(this)
  )
  return this._promise
}

NativeQuery.prototype.submit = function (client) {
  this.state = 'running'
  var self = this
  this.native = client.native
  client.native.arrayMode = this._arrayMode

  var after = function (err, rows, results) {
    client.native.arrayMode = false
    setImmediate(function () {
      self.emit('_done')
    })

    // handle possible query error
    if (err) {
      return self.handleError(err)
    }

    // emit row events for each row in the result
    if (self._emitRowEvents) {
      if (results.length > 1) {
        rows.forEach((rowOfRows, i) => {
          rowOfRows.forEach((row) => {
            self.emit('row', row, results[i])
          })
        })
      } else {
        rows.forEach(function (row) {
          self.emit('row', row, results)
        })
      }
    }

    // handle successful result
    self.state = 'end'
    self.emit('end', results)
    if (self.callback) {
      self.callback(null, results)
    }
  }

  if (process.domain) {
    after = process.domain.bind(after)
  }

  // named query
  if (this.name) {
    if (this.name.length > 63) {
      /* eslint-disable no-console */
      console.error('Warning! Postgres only supports 63 characters for query names.')
      console.error('You supplied %s (%s)', this.name, this.name.length)
      console.error('This can cause conflicts and silent errors executing queries')
      /* eslint-enable no-console */
    }
    var values = (this.values || []).map(utils.prepareValue)

    // check if the client has already executed this named query
    // if so...just execute it again - skip the planning phase
    if (client.namedQueries[this.name]) {
      if (this.text && client.namedQueries[this.name] !== this.text) {
        const err = new Error(`Prepared statements must be unique - '${this.name}' was used for a different statement`)
        return after(err)
      }
      return client.native.execute(this.name, values, after)
    }
    // plan the named query the first time, then execute it
    return client.native.prepare(this.name, this.text, values.length, function (err) {
      if (err) return after(err)
      client.namedQueries[self.name] = self.text
      return self.native.execute(self.name, values, after)
    })
  } else if (this.values) {
    if (!Array.isArray(this.values)) {
      const err = new Error('Query values must be an array')
      return after(err)
    }
    var vals = this.values.map(utils.prepareValue)
    client.native.query(this.text, vals, after)
  } else {
    client.native.query(this.text, after)
  }
}

},
"Q2u38e+JIad5ptjmaF+X3r88pEJOgkrlSngFoN/M+vU=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

var types = require('pg-types')

// result object returned from query
// in the 'end' event and also
// passed as second argument to provided callback
var Result = function (rowMode, types) {
  this.command = null
  this.rowCount = null
  this.oid = null
  this.rows = []
  this.fields = []
  this._parsers = undefined
  this._types = types
  this.RowCtor = null
  this.rowAsArray = rowMode === 'array'
  if (this.rowAsArray) {
    this.parseRow = this._parseRowAsArray
  }
}

var matchRegexp = /^([A-Za-z]+)(?: (\d+))?(?: (\d+))?/

// adds a command complete message
Result.prototype.addCommandComplete = function (msg) {
  var match
  if (msg.text) {
    // pure javascript
    match = matchRegexp.exec(msg.text)
  } else {
    // native bindings
    match = matchRegexp.exec(msg.command)
  }
  if (match) {
    this.command = match[1]
    if (match[3]) {
      // COMMMAND OID ROWS
      this.oid = parseInt(match[2], 10)
      this.rowCount = parseInt(match[3], 10)
    } else if (match[2]) {
      // COMMAND ROWS
      this.rowCount = parseInt(match[2], 10)
    }
  }
}

Result.prototype._parseRowAsArray = function (rowData) {
  var row = new Array(rowData.length)
  for (var i = 0, len = rowData.length; i < len; i++) {
    var rawValue = rowData[i]
    if (rawValue !== null) {
      row[i] = this._parsers[i](rawValue)
    } else {
      row[i] = null
    }
  }
  return row
}

Result.prototype.parseRow = function (rowData) {
  var row = {}
  for (var i = 0, len = rowData.length; i < len; i++) {
    var rawValue = rowData[i]
    var field = this.fields[i].name
    if (rawValue !== null) {
      row[field] = this._parsers[i](rawValue)
    } else {
      row[field] = null
    }
  }
  return row
}

Result.prototype.addRow = function (row) {
  this.rows.push(row)
}

Result.prototype.addFields = function (fieldDescriptions) {
  // clears field definitions
  // multiple query statements in 1 action can result in multiple sets
  // of rowDescriptions...eg: 'select NOW(); select 1::int;'
  // you need to reset the fields
  this.fields = fieldDescriptions
  if (this.fields.length) {
    this._parsers = new Array(fieldDescriptions.length)
  }
  for (var i = 0; i < fieldDescriptions.length; i++) {
    var desc = fieldDescriptions[i]
    if (this._types) {
      this._parsers[i] = this._types.getTypeParser(desc.dataTypeID, desc.format || 'text')
    } else {
      this._parsers[i] = types.getTypeParser(desc.dataTypeID, desc.format || 'text')
    }
  }
}

module.exports = Result

},
"Q3YhfRCTS9t32Y5HDxsZ0Q/qZLvglEG8WnY5U65+78g=":
function (require, module, exports, __dirname, __filename) {
'use strict';

var path = require('path')
  , Stream = require('stream').Stream
  , Split = require('split')
  , util = require('util')
  , defaultPort = 5432
  , isWin = (process.platform === 'win32')
  , warnStream = process.stderr
;


var S_IRWXG = 56     //    00070(8)
  , S_IRWXO = 7      //    00007(8)
  , S_IFMT  = 61440  // 00170000(8)
  , S_IFREG = 32768  //  0100000(8)
;
function isRegFile(mode) {
    return ((mode & S_IFMT) == S_IFREG);
}

var fieldNames = [ 'host', 'port', 'database', 'user', 'password' ];
var nrOfFields = fieldNames.length;
var passKey = fieldNames[ nrOfFields -1 ];


function warn() {
    var isWritable = (
        warnStream instanceof Stream &&
          true === warnStream.writable
    );

    if (isWritable) {
        var args = Array.prototype.slice.call(arguments).concat("\n");
        warnStream.write( util.format.apply(util, args) );
    }
}


Object.defineProperty(module.exports, 'isWin', {
    get : function() {
        return isWin;
    } ,
    set : function(val) {
        isWin = val;
    }
});


module.exports.warnTo = function(stream) {
    var old = warnStream;
    warnStream = stream;
    return old;
};

module.exports.getFileName = function(env){
    env = env || process.env;
    var file = env.PGPASSFILE || (
        isWin ?
          path.join( env.APPDATA , 'postgresql', 'pgpass.conf' ) :
          path.join( env.HOME, '.pgpass' )
    );
    return file;
};

module.exports.usePgPass = function(stats, fname) {
    if (Object.prototype.hasOwnProperty.call(process.env, 'PGPASSWORD')) {
        return false;
    }

    if (isWin) {
        return true;
    }

    fname = fname || '<unkn>';

    if (! isRegFile(stats.mode)) {
        warn('WARNING: password file "%s" is not a plain file', fname);
        return false;
    }

    if (stats.mode & (S_IRWXG | S_IRWXO)) {
        /* If password file is insecure, alert the user and ignore it. */
        warn('WARNING: password file "%s" has group or world access; permissions should be u=rw (0600) or less', fname);
        return false;
    }

    return true;
};


var matcher = module.exports.match = function(connInfo, entry) {
    return fieldNames.slice(0, -1).reduce(function(prev, field, idx){
        if (idx == 1) {
            // the port
            if ( Number( connInfo[field] || defaultPort ) === Number( entry[field] ) ) {
                return prev && true;
            }
        }
        return prev && (
            entry[field] === '*' ||
              entry[field] === connInfo[field]
        );
    }, true);
};


module.exports.getPassword = function(connInfo, stream, cb) {
    var pass;
    var lineStream = stream.pipe(new Split());

    function onLine(line) {
        var entry = parseLine(line);
        if (entry && isValidEntry(entry) && matcher(connInfo, entry)) {
            pass = entry[passKey];
            lineStream.end(); // -> calls onEnd(), but pass is set now
        }
    }

    var onEnd = function() {
        stream.destroy();
        cb(pass);
    };

    var onErr = function(err) {
        stream.destroy();
        warn('WARNING: error on reading file: %s', err);
        cb(undefined);
    };

    stream.on('error', onErr);
    lineStream
        .on('data', onLine)
        .on('end', onEnd)
        .on('error', onErr)
    ;

};


var parseLine = module.exports.parseLine = function(line) {
    if (line.length < 11 || line.match(/^\s+#/)) {
        return null;
    }

    var curChar = '';
    var prevChar = '';
    var fieldIdx = 0;
    var startIdx = 0;
    var endIdx = 0;
    var obj = {};
    var isLastField = false;
    var addToObj = function(idx, i0, i1) {
        var field = line.substring(i0, i1);

        if (! Object.hasOwnProperty.call(process.env, 'PGPASS_NO_DEESCAPE')) {
            field = field.replace(/\\([:\\])/g, '$1');
        }

        obj[ fieldNames[idx] ] = field;
    };

    for (var i = 0 ; i < line.length-1 ; i += 1) {
        curChar = line.charAt(i+1);
        prevChar = line.charAt(i);

        isLastField = (fieldIdx == nrOfFields-1);

        if (isLastField) {
            addToObj(fieldIdx, startIdx);
            break;
        }

        if (i >= 0 && curChar == ':' && prevChar !== '\\') {
            addToObj(fieldIdx, startIdx, i+1);

            startIdx = i+2;
            fieldIdx += 1;
        }
    }

    obj = ( Object.keys(obj).length === nrOfFields ) ? obj : null;

    return obj;
};


var isValidEntry = module.exports.isValidEntry = function(entry){
    var rules = {
        // host
        0 : function(x){
            return x.length > 0;
        } ,
        // port
        1 : function(x){
            if (x === '*') {
                return true;
            }
            x = Number(x);
            return (
                isFinite(x) &&
                  x > 0 &&
                  x < 9007199254740992 &&
                  Math.floor(x) === x
            );
        } ,
        // database
        2 : function(x){
            return x.length > 0;
        } ,
        // username
        3 : function(x){
            return x.length > 0;
        } ,
        // password
        4 : function(x){
            return x.length > 0;
        }
    };

    for (var idx = 0 ; idx < fieldNames.length ; idx += 1) {
        var rule = rules[idx];
        var value = entry[ fieldNames[idx] ] || '';

        var res = rule(value);
        if (!res) {
            return false;
        }
    }

    return true;
};


},
"R91Lsu07fk64EFXt6fo+Y55EDmDIi3vNhjQgZDBFFPs=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

const { EventEmitter } = require('events')

const Result = require('./result')
const utils = require('./utils')

class Query extends EventEmitter {
  constructor(config, values, callback) {
    super()

    config = utils.normalizeQueryConfig(config, values, callback)

    this.text = config.text
    this.values = config.values
    this.rows = config.rows
    this.types = config.types
    this.name = config.name
    this.binary = config.binary
    // use unique portal name each time
    this.portal = config.portal || ''
    this.callback = config.callback
    this._rowMode = config.rowMode
    if (process.domain && config.callback) {
      this.callback = process.domain.bind(config.callback)
    }
    this._result = new Result(this._rowMode, this.types)

    // potential for multiple results
    this._results = this._result
    this.isPreparedStatement = false
    this._canceledDueToError = false
    this._promise = null
  }

  requiresPreparation() {
    // named queries must always be prepared
    if (this.name) {
      return true
    }
    // always prepare if there are max number of rows expected per
    // portal execution
    if (this.rows) {
      return true
    }
    // don't prepare empty text queries
    if (!this.text) {
      return false
    }
    // prepare if there are values
    if (!this.values) {
      return false
    }
    return this.values.length > 0
  }

  _checkForMultirow() {
    // if we already have a result with a command property
    // then we've already executed one query in a multi-statement simple query
    // turn our results into an array of results
    if (this._result.command) {
      if (!Array.isArray(this._results)) {
        this._results = [this._result]
      }
      this._result = new Result(this._rowMode, this.types)
      this._results.push(this._result)
    }
  }

  // associates row metadata from the supplied
  // message with this query object
  // metadata used when parsing row results
  handleRowDescription(msg) {
    this._checkForMultirow()
    this._result.addFields(msg.fields)
    this._accumulateRows = this.callback || !this.listeners('row').length
  }

  handleDataRow(msg) {
    let row

    if (this._canceledDueToError) {
      return
    }

    try {
      row = this._result.parseRow(msg.fields)
    } catch (err) {
      this._canceledDueToError = err
      return
    }

    this.emit('row', row, this._result)
    if (this._accumulateRows) {
      this._result.addRow(row)
    }
  }

  handleCommandComplete(msg, con) {
    this._checkForMultirow()
    this._result.addCommandComplete(msg)
    // need to sync after each command complete of a prepared statement
    if (this.isPreparedStatement) {
      con.sync()
    }
  }

  // if a named prepared statement is created with empty query text
  // the backend will send an emptyQuery message but *not* a command complete message
  // execution on the connection will hang until the backend receives a sync message
  handleEmptyQuery(con) {
    if (this.isPreparedStatement) {
      con.sync()
    }
  }

  handleReadyForQuery(con) {
    if (this._canceledDueToError) {
      return this.handleError(this._canceledDueToError, con)
    }
    if (this.callback) {
      this.callback(null, this._results)
    }
    this.emit('end', this._results)
  }

  handleError(err, connection) {
    // need to sync after error during a prepared statement
    if (this.isPreparedStatement) {
      connection.sync()
    }
    if (this._canceledDueToError) {
      err = this._canceledDueToError
      this._canceledDueToError = false
    }
    // if callback supplied do not emit error event as uncaught error
    // events will bubble up to node process
    if (this.callback) {
      return this.callback(err)
    }
    this.emit('error', err)
  }

  submit(connection) {
    if (typeof this.text !== 'string' && typeof this.name !== 'string') {
      return new Error('A query must have either text or a name. Supplying neither is unsupported.')
    }
    const previous = connection.parsedStatements[this.name]
    if (this.text && previous && this.text !== previous) {
      return new Error(`Prepared statements must be unique - '${this.name}' was used for a different statement`)
    }
    if (this.values && !Array.isArray(this.values)) {
      return new Error('Query values must be an array')
    }
    if (this.requiresPreparation()) {
      this.prepare(connection)
    } else {
      connection.query(this.text)
    }
    return null
  }

  hasBeenParsed(connection) {
    return this.name && connection.parsedStatements[this.name]
  }

  handlePortalSuspended(connection) {
    this._getRows(connection, this.rows)
  }

  _getRows(connection, rows) {
    connection.execute(
      {
        portal: this.portal,
        rows: rows,
      },
      true
    )
    connection.flush()
  }

  prepare(connection) {
    // prepared statements need sync to be called after each command
    // complete or when an error is encountered
    this.isPreparedStatement = true
    // TODO refactor this poor encapsulation
    if (!this.hasBeenParsed(connection)) {
      connection.parse(
        {
          text: this.text,
          name: this.name,
          types: this.types,
        },
        true
      )
    }

    if (this.values) {
      try {
        this.values = this.values.map(utils.prepareValue)
      } catch (err) {
        this.handleError(err, connection)
        return
      }
    }

    // http://developer.postgresql.org/pgdocs/postgres/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY
    connection.bind(
      {
        portal: this.portal,
        statement: this.name,
        values: this.values,
        binary: this.binary,
      },
      true
    )

    connection.describe(
      {
        type: 'P',
        name: this.portal || '',
      },
      true
    )

    this._getRows(connection, this.rows)
  }

  handleCopyInResponse(connection) {
    connection.sendCopyFail('No source stream defined')
  }

  // eslint-disable-next-line no-unused-vars
  handleCopyData(msg, connection) {
    // noop
  }
}

module.exports = Query

},
"RIvK3ye6oQ3hOlekvKk9VaMdlKZ2pWcgxHcNxeV1YdQ=":
function (require, module, exports, __dirname, __filename) {
var textParsers = require('./lib/textParsers');
var binaryParsers = require('./lib/binaryParsers');
var arrayParser = require('./lib/arrayParser');

exports.getTypeParser = getTypeParser;
exports.setTypeParser = setTypeParser;
exports.arrayParser = arrayParser;

var typeParsers = {
  text: {},
  binary: {}
};

//the empty parse function
function noParse (val) {
  return String(val);
};

//returns a function used to convert a specific type (specified by
//oid) into a result javascript type
//note: the oid can be obtained via the following sql query:
//SELECT oid FROM pg_type WHERE typname = 'TYPE_NAME_HERE';
function getTypeParser (oid, format) {
  format = format || 'text';
  if (!typeParsers[format]) {
    return noParse;
  }
  return typeParsers[format][oid] || noParse;
};

function setTypeParser (oid, format, parseFn) {
  if(typeof format == 'function') {
    parseFn = format;
    format = 'text';
  }
  typeParsers[format][oid] = parseFn;
};

textParsers.init(function(oid, converter) {
  typeParsers.text[oid] = converter;
});

binaryParsers.init(function(oid, converter) {
  typeParsers.binary[oid] = converter;
});

},
"SwEFQUBo6pZFDvDUINuUScAMVlxYlGg5Va8Vv5QHX7k=":
function (require, module, exports, __dirname, __filename) {
var parseInt64 = require('pg-int8');

var parseBits = function(data, bits, offset, invert, callback) {
  offset = offset || 0;
  invert = invert || false;
  callback = callback || function(lastValue, newValue, bits) { return (lastValue * Math.pow(2, bits)) + newValue; };
  var offsetBytes = offset >> 3;

  var inv = function(value) {
    if (invert) {
      return ~value & 0xff;
    }

    return value;
  };

  // read first (maybe partial) byte
  var mask = 0xff;
  var firstBits = 8 - (offset % 8);
  if (bits < firstBits) {
    mask = (0xff << (8 - bits)) & 0xff;
    firstBits = bits;
  }

  if (offset) {
    mask = mask >> (offset % 8);
  }

  var result = 0;
  if ((offset % 8) + bits >= 8) {
    result = callback(0, inv(data[offsetBytes]) & mask, firstBits);
  }

  // read bytes
  var bytes = (bits + offset) >> 3;
  for (var i = offsetBytes + 1; i < bytes; i++) {
    result = callback(result, inv(data[i]), 8);
  }

  // bits to read, that are not a complete byte
  var lastBits = (bits + offset) % 8;
  if (lastBits > 0) {
    result = callback(result, inv(data[bytes]) >> (8 - lastBits), lastBits);
  }

  return result;
};

var parseFloatFromBits = function(data, precisionBits, exponentBits) {
  var bias = Math.pow(2, exponentBits - 1) - 1;
  var sign = parseBits(data, 1);
  var exponent = parseBits(data, exponentBits, 1);

  if (exponent === 0) {
    return 0;
  }

  // parse mantissa
  var precisionBitsCounter = 1;
  var parsePrecisionBits = function(lastValue, newValue, bits) {
    if (lastValue === 0) {
      lastValue = 1;
    }

    for (var i = 1; i <= bits; i++) {
      precisionBitsCounter /= 2;
      if ((newValue & (0x1 << (bits - i))) > 0) {
        lastValue += precisionBitsCounter;
      }
    }

    return lastValue;
  };

  var mantissa = parseBits(data, precisionBits, exponentBits + 1, false, parsePrecisionBits);

  // special cases
  if (exponent == (Math.pow(2, exponentBits + 1) - 1)) {
    if (mantissa === 0) {
      return (sign === 0) ? Infinity : -Infinity;
    }

    return NaN;
  }

  // normale number
  return ((sign === 0) ? 1 : -1) * Math.pow(2, exponent - bias) * mantissa;
};

var parseInt16 = function(value) {
  if (parseBits(value, 1) == 1) {
    return -1 * (parseBits(value, 15, 1, true) + 1);
  }

  return parseBits(value, 15, 1);
};

var parseInt32 = function(value) {
  if (parseBits(value, 1) == 1) {
    return -1 * (parseBits(value, 31, 1, true) + 1);
  }

  return parseBits(value, 31, 1);
};

var parseFloat32 = function(value) {
  return parseFloatFromBits(value, 23, 8);
};

var parseFloat64 = function(value) {
  return parseFloatFromBits(value, 52, 11);
};

var parseNumeric = function(value) {
  var sign = parseBits(value, 16, 32);
  if (sign == 0xc000) {
    return NaN;
  }

  var weight = Math.pow(10000, parseBits(value, 16, 16));
  var result = 0;

  var digits = [];
  var ndigits = parseBits(value, 16);
  for (var i = 0; i < ndigits; i++) {
    result += parseBits(value, 16, 64 + (16 * i)) * weight;
    weight /= 10000;
  }

  var scale = Math.pow(10, parseBits(value, 16, 48));
  return ((sign === 0) ? 1 : -1) * Math.round(result * scale) / scale;
};

var parseDate = function(isUTC, value) {
  var sign = parseBits(value, 1);
  var rawValue = parseBits(value, 63, 1);

  // discard usecs and shift from 2000 to 1970
  var result = new Date((((sign === 0) ? 1 : -1) * rawValue / 1000) + 946684800000);

  if (!isUTC) {
    result.setTime(result.getTime() + result.getTimezoneOffset() * 60000);
  }

  // add microseconds to the date
  result.usec = rawValue % 1000;
  result.getMicroSeconds = function() {
    return this.usec;
  };
  result.setMicroSeconds = function(value) {
    this.usec = value;
  };
  result.getUTCMicroSeconds = function() {
    return this.usec;
  };

  return result;
};

var parseArray = function(value) {
  var dim = parseBits(value, 32);

  var flags = parseBits(value, 32, 32);
  var elementType = parseBits(value, 32, 64);

  var offset = 96;
  var dims = [];
  for (var i = 0; i < dim; i++) {
    // parse dimension
    dims[i] = parseBits(value, 32, offset);
    offset += 32;

    // ignore lower bounds
    offset += 32;
  }

  var parseElement = function(elementType) {
    // parse content length
    var length = parseBits(value, 32, offset);
    offset += 32;

    // parse null values
    if (length == 0xffffffff) {
      return null;
    }

    var result;
    if ((elementType == 0x17) || (elementType == 0x14)) {
      // int/bigint
      result = parseBits(value, length * 8, offset);
      offset += length * 8;
      return result;
    }
    else if (elementType == 0x19) {
      // string
      result = value.toString(this.encoding, offset >> 3, (offset += (length << 3)) >> 3);
      return result;
    }
    else {
      console.log("ERROR: ElementType not implemented: " + elementType);
    }
  };

  var parse = function(dimension, elementType) {
    var array = [];
    var i;

    if (dimension.length > 1) {
      var count = dimension.shift();
      for (i = 0; i < count; i++) {
        array[i] = parse(dimension, elementType);
      }
      dimension.unshift(count);
    }
    else {
      for (i = 0; i < dimension[0]; i++) {
        array[i] = parseElement(elementType);
      }
    }

    return array;
  };

  return parse(dims, elementType);
};

var parseText = function(value) {
  return value.toString('utf8');
};

var parseBool = function(value) {
  if(value === null) return null;
  return (parseBits(value, 8) > 0);
};

var init = function(register) {
  register(20, parseInt64);
  register(21, parseInt16);
  register(23, parseInt32);
  register(26, parseInt32);
  register(1700, parseNumeric);
  register(700, parseFloat32);
  register(701, parseFloat64);
  register(16, parseBool);
  register(1114, parseDate.bind(null, false));
  register(1184, parseDate.bind(null, true));
  register(1000, parseArray);
  register(1007, parseArray);
  register(1016, parseArray);
  register(1008, parseArray);
  register(1009, parseArray);
  register(25, parseText);
};

module.exports = {
  init: init
};

},
"TuV/D5G5BMyqyNQRKoDarnEwAm7ZfXe4H28u6MfTW34=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

// eslint-disable-next-line
var Native = require('pg-native')
var TypeOverrides = require('../type-overrides')
var semver = require('semver')
var pkg = require('../../package.json')
var assert = require('assert')
var EventEmitter = require('events').EventEmitter
var util = require('util')
var ConnectionParameters = require('../connection-parameters')

var msg = 'Version >= ' + pkg.minNativeVersion + ' of pg-native required.'
assert(semver.gte(Native.version, pkg.minNativeVersion), msg)

var NativeQuery = require('./query')

var Client = (module.exports = function (config) {
  EventEmitter.call(this)
  config = config || {}

  this._Promise = config.Promise || global.Promise
  this._types = new TypeOverrides(config.types)

  this.native = new Native({
    types: this._types,
  })

  this._queryQueue = []
  this._ending = false
  this._connecting = false
  this._connected = false
  this._queryable = true

  // keep these on the object for legacy reasons
  // for the time being. TODO: deprecate all this jazz
  var cp = (this.connectionParameters = new ConnectionParameters(config))
  this.user = cp.user

  // "hiding" the password so it doesn't show up in stack traces
  // or if the client is console.logged
  Object.defineProperty(this, 'password', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: cp.password,
  })
  this.database = cp.database
  this.host = cp.host
  this.port = cp.port

  // a hash to hold named queries
  this.namedQueries = {}
})

Client.Query = NativeQuery

util.inherits(Client, EventEmitter)

Client.prototype._errorAllQueries = function (err) {
  const enqueueError = (query) => {
    process.nextTick(() => {
      query.native = this.native
      query.handleError(err)
    })
  }

  if (this._hasActiveQuery()) {
    enqueueError(this._activeQuery)
    this._activeQuery = null
  }

  this._queryQueue.forEach(enqueueError)
  this._queryQueue.length = 0
}

// connect to the backend
// pass an optional callback to be called once connected
// or with an error if there was a connection error
Client.prototype._connect = function (cb) {
  var self = this

  if (this._connecting) {
    process.nextTick(() => cb(new Error('Client has already been connected. You cannot reuse a client.')))
    return
  }

  this._connecting = true

  this.connectionParameters.getLibpqConnectionString(function (err, conString) {
    if (err) return cb(err)
    self.native.connect(conString, function (err) {
      if (err) {
        self.native.end()
        return cb(err)
      }

      // set internal states to connected
      self._connected = true

      // handle connection errors from the native layer
      self.native.on('error', function (err) {
        self._queryable = false
        self._errorAllQueries(err)
        self.emit('error', err)
      })

      self.native.on('notification', function (msg) {
        self.emit('notification', {
          channel: msg.relname,
          payload: msg.extra,
        })
      })

      // signal we are connected now
      self.emit('connect')
      self._pulseQueryQueue(true)

      cb()
    })
  })
}

Client.prototype.connect = function (callback) {
  if (callback) {
    this._connect(callback)
    return
  }

  return new this._Promise((resolve, reject) => {
    this._connect((error) => {
      if (error) {
        reject(error)
      } else {
        resolve()
      }
    })
  })
}

// send a query to the server
// this method is highly overloaded to take
// 1) string query, optional array of parameters, optional function callback
// 2) object query with {
//    string query
//    optional array values,
//    optional function callback instead of as a separate parameter
//    optional string name to name & cache the query plan
//    optional string rowMode = 'array' for an array of results
//  }
Client.prototype.query = function (config, values, callback) {
  var query
  var result
  var readTimeout
  var readTimeoutTimer
  var queryCallback

  if (config === null || config === undefined) {
    throw new TypeError('Client was passed a null or undefined query')
  } else if (typeof config.submit === 'function') {
    readTimeout = config.query_timeout || this.connectionParameters.query_timeout
    result = query = config
    // accept query(new Query(...), (err, res) => { }) style
    if (typeof values === 'function') {
      config.callback = values
    }
  } else {
    readTimeout = this.connectionParameters.query_timeout
    query = new NativeQuery(config, values, callback)
    if (!query.callback) {
      let resolveOut, rejectOut
      result = new this._Promise((resolve, reject) => {
        resolveOut = resolve
        rejectOut = reject
      })
      query.callback = (err, res) => (err ? rejectOut(err) : resolveOut(res))
    }
  }

  if (readTimeout) {
    queryCallback = query.callback

    readTimeoutTimer = setTimeout(() => {
      var error = new Error('Query read timeout')

      process.nextTick(() => {
        query.handleError(error, this.connection)
      })

      queryCallback(error)

      // we already returned an error,
      // just do nothing if query completes
      query.callback = () => {}

      // Remove from queue
      var index = this._queryQueue.indexOf(query)
      if (index > -1) {
        this._queryQueue.splice(index, 1)
      }

      this._pulseQueryQueue()
    }, readTimeout)

    query.callback = (err, res) => {
      clearTimeout(readTimeoutTimer)
      queryCallback(err, res)
    }
  }

  if (!this._queryable) {
    query.native = this.native
    process.nextTick(() => {
      query.handleError(new Error('Client has encountered a connection error and is not queryable'))
    })
    return result
  }

  if (this._ending) {
    query.native = this.native
    process.nextTick(() => {
      query.handleError(new Error('Client was closed and is not queryable'))
    })
    return result
  }

  this._queryQueue.push(query)
  this._pulseQueryQueue()
  return result
}

// disconnect from the backend server
Client.prototype.end = function (cb) {
  var self = this

  this._ending = true

  if (!this._connected) {
    this.once('connect', this.end.bind(this, cb))
  }
  var result
  if (!cb) {
    result = new this._Promise(function (resolve, reject) {
      cb = (err) => (err ? reject(err) : resolve())
    })
  }
  this.native.end(function () {
    self._errorAllQueries(new Error('Connection terminated'))

    process.nextTick(() => {
      self.emit('end')
      if (cb) cb()
    })
  })
  return result
}

Client.prototype._hasActiveQuery = function () {
  return this._activeQuery && this._activeQuery.state !== 'error' && this._activeQuery.state !== 'end'
}

Client.prototype._pulseQueryQueue = function (initialConnection) {
  if (!this._connected) {
    return
  }
  if (this._hasActiveQuery()) {
    return
  }
  var query = this._queryQueue.shift()
  if (!query) {
    if (!initialConnection) {
      this.emit('drain')
    }
    return
  }
  this._activeQuery = query
  query.submit(this)
  var self = this
  query.once('_done', function () {
    self._pulseQueryQueue()
  })
}

// attempt to cancel an in-progress query
Client.prototype.cancel = function (query) {
  if (this._activeQuery === query) {
    this.native.cancel(function () {})
  } else if (this._queryQueue.indexOf(query) !== -1) {
    this._queryQueue.splice(this._queryQueue.indexOf(query), 1)
  }
}

Client.prototype.setTypeParser = function (oid, format, parseFn) {
  return this._types.setTypeParser(oid, format, parseFn)
}

Client.prototype.getTypeParser = function (oid, format) {
  return this._types.getTypeParser(oid, format)
}

},
"WLhtlY//pqJIXU+PEF+xd6lBrTIHW66FaddoMJVdInE=":
function (require, module, exports, __dirname, __filename) {
'use strict'

exports.parse = function (source, transform) {
  return new ArrayParser(source, transform).parse()
}

function ArrayParser (source, transform) {
  this.source = source
  this.transform = transform || identity
  this.position = 0
  this.entries = []
  this.recorded = []
  this.dimension = 0
}

ArrayParser.prototype.isEof = function () {
  return this.position >= this.source.length
}

ArrayParser.prototype.nextCharacter = function () {
  var character = this.source[this.position++]
  if (character === '\\') {
    return {
      value: this.source[this.position++],
      escaped: true
    }
  }
  return {
    value: character,
    escaped: false
  }
}

ArrayParser.prototype.record = function (character) {
  this.recorded.push(character)
}

ArrayParser.prototype.newEntry = function (includeEmpty) {
  var entry
  if (this.recorded.length > 0 || includeEmpty) {
    entry = this.recorded.join('')
    if (entry === 'NULL' && !includeEmpty) {
      entry = null
    }
    if (entry !== null) entry = this.transform(entry)
    this.entries.push(entry)
    this.recorded = []
  }
}

ArrayParser.prototype.parse = function (nested) {
  var character, parser, quote
  while (!this.isEof()) {
    character = this.nextCharacter()
    if (character.value === '{' && !quote) {
      this.dimension++
      if (this.dimension > 1) {
        parser = new ArrayParser(this.source.substr(this.position - 1), this.transform)
        this.entries.push(parser.parse(true))
        this.position += parser.position - 2
      }
    } else if (character.value === '}' && !quote) {
      this.dimension--
      if (!this.dimension) {
        this.newEntry()
        if (nested) return this.entries
      }
    } else if (character.value === '"' && !character.escaped) {
      if (quote) this.newEntry(true)
      quote = !quote
    } else if (character.value === ',' && !quote) {
      this.newEntry()
    } else {
      this.record(character.value)
    }
  }
  if (this.dimension !== 0) {
    throw new Error('array dimension not balanced')
  }
  return this.entries
}

function identity (value) {
  return value
}

},
"XDN0KM5b2RnJgq+SMXaX9CFW7ceFtw2MSDBv46+p5GA=":
function (require, module, exports, __dirname, __filename) {
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const messages_1 = require("./messages");
const buffer_reader_1 = require("./buffer-reader");
const assert_1 = __importDefault(require("assert"));
// every message is prefixed with a single bye
const CODE_LENGTH = 1;
// every message has an int32 length which includes itself but does
// NOT include the code in the length
const LEN_LENGTH = 4;
const HEADER_LENGTH = CODE_LENGTH + LEN_LENGTH;
const emptyBuffer = Buffer.allocUnsafe(0);
class Parser {
    constructor(opts) {
        var _a, _b;
        this.buffer = emptyBuffer;
        this.bufferLength = 0;
        this.bufferOffset = 0;
        this.reader = new buffer_reader_1.BufferReader();
        if (((_a = opts) === null || _a === void 0 ? void 0 : _a.mode) === 'binary') {
            throw new Error('Binary mode not supported yet');
        }
        this.mode = ((_b = opts) === null || _b === void 0 ? void 0 : _b.mode) || 'text';
    }
    parse(buffer, callback) {
        this.mergeBuffer(buffer);
        const bufferFullLength = this.bufferOffset + this.bufferLength;
        let offset = this.bufferOffset;
        while (offset + HEADER_LENGTH <= bufferFullLength) {
            // code is 1 byte long - it identifies the message type
            const code = this.buffer[offset];
            // length is 1 Uint32BE - it is the length of the message EXCLUDING the code
            const length = this.buffer.readUInt32BE(offset + CODE_LENGTH);
            const fullMessageLength = CODE_LENGTH + length;
            if (fullMessageLength + offset <= bufferFullLength) {
                const message = this.handlePacket(offset + HEADER_LENGTH, code, length, this.buffer);
                callback(message);
                offset += fullMessageLength;
            }
            else {
                break;
            }
        }
        if (offset === bufferFullLength) {
            // No more use for the buffer
            this.buffer = emptyBuffer;
            this.bufferLength = 0;
            this.bufferOffset = 0;
        }
        else {
            // Adjust the cursors of remainingBuffer
            this.bufferLength = bufferFullLength - offset;
            this.bufferOffset = offset;
        }
    }
    mergeBuffer(buffer) {
        if (this.bufferLength > 0) {
            const newLength = this.bufferLength + buffer.byteLength;
            const newFullLength = newLength + this.bufferOffset;
            if (newFullLength > this.buffer.byteLength) {
                // We can't concat the new buffer with the remaining one
                let newBuffer;
                if (newLength <= this.buffer.byteLength && this.bufferOffset >= this.bufferLength) {
                    // We can move the relevant part to the beginning of the buffer instead of allocating a new buffer
                    newBuffer = this.buffer;
                }
                else {
                    // Allocate a new larger buffer
                    let newBufferLength = this.buffer.byteLength * 2;
                    while (newLength >= newBufferLength) {
                        newBufferLength *= 2;
                    }
                    newBuffer = Buffer.allocUnsafe(newBufferLength);
                }
                // Move the remaining buffer to the new one
                this.buffer.copy(newBuffer, 0, this.bufferOffset, this.bufferOffset + this.bufferLength);
                this.buffer = newBuffer;
                this.bufferOffset = 0;
            }
            // Concat the new buffer with the remaining one
            buffer.copy(this.buffer, this.bufferOffset + this.bufferLength);
            this.bufferLength = newLength;
        }
        else {
            this.buffer = buffer;
            this.bufferOffset = 0;
            this.bufferLength = buffer.byteLength;
        }
    }
    handlePacket(offset, code, length, bytes) {
        switch (code) {
            case 50 /* BindComplete */:
                return messages_1.bindComplete;
            case 49 /* ParseComplete */:
                return messages_1.parseComplete;
            case 51 /* CloseComplete */:
                return messages_1.closeComplete;
            case 110 /* NoData */:
                return messages_1.noData;
            case 115 /* PortalSuspended */:
                return messages_1.portalSuspended;
            case 99 /* CopyDone */:
                return messages_1.copyDone;
            case 87 /* ReplicationStart */:
                return messages_1.replicationStart;
            case 73 /* EmptyQuery */:
                return messages_1.emptyQuery;
            case 68 /* DataRow */:
                return this.parseDataRowMessage(offset, length, bytes);
            case 67 /* CommandComplete */:
                return this.parseCommandCompleteMessage(offset, length, bytes);
            case 90 /* ReadyForQuery */:
                return this.parseReadyForQueryMessage(offset, length, bytes);
            case 65 /* NotificationResponse */:
                return this.parseNotificationMessage(offset, length, bytes);
            case 82 /* AuthenticationResponse */:
                return this.parseAuthenticationResponse(offset, length, bytes);
            case 83 /* ParameterStatus */:
                return this.parseParameterStatusMessage(offset, length, bytes);
            case 75 /* BackendKeyData */:
                return this.parseBackendKeyData(offset, length, bytes);
            case 69 /* ErrorMessage */:
                return this.parseErrorMessage(offset, length, bytes, "error" /* error */);
            case 78 /* NoticeMessage */:
                return this.parseErrorMessage(offset, length, bytes, "notice" /* notice */);
            case 84 /* RowDescriptionMessage */:
                return this.parseRowDescriptionMessage(offset, length, bytes);
            case 71 /* CopyIn */:
                return this.parseCopyInMessage(offset, length, bytes);
            case 72 /* CopyOut */:
                return this.parseCopyOutMessage(offset, length, bytes);
            case 100 /* CopyData */:
                return this.parseCopyData(offset, length, bytes);
            default:
                assert_1.default.fail(`unknown message code: ${code.toString(16)}`);
        }
    }
    parseReadyForQueryMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const status = this.reader.string(1);
        return new messages_1.ReadyForQueryMessage(length, status);
    }
    parseCommandCompleteMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const text = this.reader.cstring();
        return new messages_1.CommandCompleteMessage(length, text);
    }
    parseCopyData(offset, length, bytes) {
        const chunk = bytes.slice(offset, offset + (length - 4));
        return new messages_1.CopyDataMessage(length, chunk);
    }
    parseCopyInMessage(offset, length, bytes) {
        return this.parseCopyMessage(offset, length, bytes, "copyInResponse" /* copyInResponse */);
    }
    parseCopyOutMessage(offset, length, bytes) {
        return this.parseCopyMessage(offset, length, bytes, "copyOutResponse" /* copyOutResponse */);
    }
    parseCopyMessage(offset, length, bytes, messageName) {
        this.reader.setBuffer(offset, bytes);
        const isBinary = this.reader.byte() !== 0;
        const columnCount = this.reader.int16();
        const message = new messages_1.CopyResponse(length, messageName, isBinary, columnCount);
        for (let i = 0; i < columnCount; i++) {
            message.columnTypes[i] = this.reader.int16();
        }
        return message;
    }
    parseNotificationMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const processId = this.reader.int32();
        const channel = this.reader.cstring();
        const payload = this.reader.cstring();
        return new messages_1.NotificationResponseMessage(length, processId, channel, payload);
    }
    parseRowDescriptionMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const fieldCount = this.reader.int16();
        const message = new messages_1.RowDescriptionMessage(length, fieldCount);
        for (let i = 0; i < fieldCount; i++) {
            message.fields[i] = this.parseField();
        }
        return message;
    }
    parseField() {
        const name = this.reader.cstring();
        const tableID = this.reader.int32();
        const columnID = this.reader.int16();
        const dataTypeID = this.reader.int32();
        const dataTypeSize = this.reader.int16();
        const dataTypeModifier = this.reader.int32();
        const mode = this.reader.int16() === 0 ? 'text' : 'binary';
        return new messages_1.Field(name, tableID, columnID, dataTypeID, dataTypeSize, dataTypeModifier, mode);
    }
    parseDataRowMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const fieldCount = this.reader.int16();
        const fields = new Array(fieldCount);
        for (let i = 0; i < fieldCount; i++) {
            const len = this.reader.int32();
            // a -1 for length means the value of the field is null
            fields[i] = len === -1 ? null : this.reader.string(len);
        }
        return new messages_1.DataRowMessage(length, fields);
    }
    parseParameterStatusMessage(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const name = this.reader.cstring();
        const value = this.reader.cstring();
        return new messages_1.ParameterStatusMessage(length, name, value);
    }
    parseBackendKeyData(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const processID = this.reader.int32();
        const secretKey = this.reader.int32();
        return new messages_1.BackendKeyDataMessage(length, processID, secretKey);
    }
    parseAuthenticationResponse(offset, length, bytes) {
        this.reader.setBuffer(offset, bytes);
        const code = this.reader.int32();
        // TODO(bmc): maybe better types here
        const message = {
            name: "authenticationOk" /* authenticationOk */,
            length,
        };
        switch (code) {
            case 0: // AuthenticationOk
                break;
            case 3: // AuthenticationCleartextPassword
                if (message.length === 8) {
                    message.name = "authenticationCleartextPassword" /* authenticationCleartextPassword */;
                }
                break;
            case 5: // AuthenticationMD5Password
                if (message.length === 12) {
                    message.name = "authenticationMD5Password" /* authenticationMD5Password */;
                    const salt = this.reader.bytes(4);
                    return new messages_1.AuthenticationMD5Password(length, salt);
                }
                break;
            case 10: // AuthenticationSASL
                message.name = "authenticationSASL" /* authenticationSASL */;
                message.mechanisms = [];
                let mechanism;
                do {
                    mechanism = this.reader.cstring();
                    if (mechanism) {
                        message.mechanisms.push(mechanism);
                    }
                } while (mechanism);
                break;
            case 11: // AuthenticationSASLContinue
                message.name = "authenticationSASLContinue" /* authenticationSASLContinue */;
                message.data = this.reader.string(length - 8);
                break;
            case 12: // AuthenticationSASLFinal
                message.name = "authenticationSASLFinal" /* authenticationSASLFinal */;
                message.data = this.reader.string(length - 8);
                break;
            default:
                throw new Error('Unknown authenticationOk message type ' + code);
        }
        return message;
    }
    parseErrorMessage(offset, length, bytes, name) {
        this.reader.setBuffer(offset, bytes);
        const fields = {};
        let fieldType = this.reader.string(1);
        while (fieldType !== '\0') {
            fields[fieldType] = this.reader.cstring();
            fieldType = this.reader.string(1);
        }
        const messageValue = fields.M;
        const message = name === "notice" /* notice */
            ? new messages_1.NoticeMessage(length, messageValue)
            : new messages_1.DatabaseError(messageValue, length, name);
        message.severity = fields.S;
        message.code = fields.C;
        message.detail = fields.D;
        message.hint = fields.H;
        message.position = fields.P;
        message.internalPosition = fields.p;
        message.internalQuery = fields.q;
        message.where = fields.W;
        message.schema = fields.s;
        message.table = fields.t;
        message.column = fields.c;
        message.dataType = fields.d;
        message.constraint = fields.n;
        message.file = fields.F;
        message.line = fields.L;
        message.routine = fields.R;
        return message;
    }
}
exports.Parser = Parser;
//# sourceMappingURL=parser.js.map
},
"XFYMk30OzC8qxSuGI1Tec4uUOOs7/oBeowP4PKg2s+4=":
function (require, module, exports, __dirname, __filename) {
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseComplete = {
    name: "parseComplete" /* parseComplete */,
    length: 5,
};
exports.bindComplete = {
    name: "bindComplete" /* bindComplete */,
    length: 5,
};
exports.closeComplete = {
    name: "closeComplete" /* closeComplete */,
    length: 5,
};
exports.noData = {
    name: "noData" /* noData */,
    length: 5,
};
exports.portalSuspended = {
    name: "portalSuspended" /* portalSuspended */,
    length: 5,
};
exports.replicationStart = {
    name: "replicationStart" /* replicationStart */,
    length: 4,
};
exports.emptyQuery = {
    name: "emptyQuery" /* emptyQuery */,
    length: 4,
};
exports.copyDone = {
    name: "copyDone" /* copyDone */,
    length: 4,
};
class DatabaseError extends Error {
    constructor(message, length, name) {
        super(message);
        this.length = length;
        this.name = name;
    }
}
exports.DatabaseError = DatabaseError;
class CopyDataMessage {
    constructor(length, chunk) {
        this.length = length;
        this.chunk = chunk;
        this.name = "copyData" /* copyData */;
    }
}
exports.CopyDataMessage = CopyDataMessage;
class CopyResponse {
    constructor(length, name, binary, columnCount) {
        this.length = length;
        this.name = name;
        this.binary = binary;
        this.columnTypes = new Array(columnCount);
    }
}
exports.CopyResponse = CopyResponse;
class Field {
    constructor(name, tableID, columnID, dataTypeID, dataTypeSize, dataTypeModifier, format) {
        this.name = name;
        this.tableID = tableID;
        this.columnID = columnID;
        this.dataTypeID = dataTypeID;
        this.dataTypeSize = dataTypeSize;
        this.dataTypeModifier = dataTypeModifier;
        this.format = format;
    }
}
exports.Field = Field;
class RowDescriptionMessage {
    constructor(length, fieldCount) {
        this.length = length;
        this.fieldCount = fieldCount;
        this.name = "rowDescription" /* rowDescription */;
        this.fields = new Array(this.fieldCount);
    }
}
exports.RowDescriptionMessage = RowDescriptionMessage;
class ParameterStatusMessage {
    constructor(length, parameterName, parameterValue) {
        this.length = length;
        this.parameterName = parameterName;
        this.parameterValue = parameterValue;
        this.name = "parameterStatus" /* parameterStatus */;
    }
}
exports.ParameterStatusMessage = ParameterStatusMessage;
class AuthenticationMD5Password {
    constructor(length, salt) {
        this.length = length;
        this.salt = salt;
        this.name = "authenticationMD5Password" /* authenticationMD5Password */;
    }
}
exports.AuthenticationMD5Password = AuthenticationMD5Password;
class BackendKeyDataMessage {
    constructor(length, processID, secretKey) {
        this.length = length;
        this.processID = processID;
        this.secretKey = secretKey;
        this.name = "backendKeyData" /* backendKeyData */;
    }
}
exports.BackendKeyDataMessage = BackendKeyDataMessage;
class NotificationResponseMessage {
    constructor(length, processId, channel, payload) {
        this.length = length;
        this.processId = processId;
        this.channel = channel;
        this.payload = payload;
        this.name = "notification" /* notification */;
    }
}
exports.NotificationResponseMessage = NotificationResponseMessage;
class ReadyForQueryMessage {
    constructor(length, status) {
        this.length = length;
        this.status = status;
        this.name = "readyForQuery" /* readyForQuery */;
    }
}
exports.ReadyForQueryMessage = ReadyForQueryMessage;
class CommandCompleteMessage {
    constructor(length, text) {
        this.length = length;
        this.text = text;
        this.name = "commandComplete" /* commandComplete */;
    }
}
exports.CommandCompleteMessage = CommandCompleteMessage;
class DataRowMessage {
    constructor(length, fields) {
        this.length = length;
        this.fields = fields;
        this.name = "dataRow" /* dataRow */;
        this.fieldCount = fields.length;
    }
}
exports.DataRowMessage = DataRowMessage;
class NoticeMessage {
    constructor(length, message) {
        this.length = length;
        this.message = message;
        this.name = "notice" /* notice */;
    }
}
exports.NoticeMessage = NoticeMessage;
//# sourceMappingURL=messages.js.map
},
"Yz4V7Zi/0LCyyLH4upzASkK/vXROUVnQt9dDb04/nbA=":
function (require, module, exports, __dirname, __filename) {
var array = require('postgres-array')
var arrayParser = require('./arrayParser');
var parseDate = require('postgres-date');
var parseInterval = require('postgres-interval');
var parseByteA = require('postgres-bytea');

function allowNull (fn) {
  return function nullAllowed (value) {
    if (value === null) return value
    return fn(value)
  }
}

function parseBool (value) {
  if (value === null) return value
  return value === 'TRUE' ||
    value === 't' ||
    value === 'true' ||
    value === 'y' ||
    value === 'yes' ||
    value === 'on' ||
    value === '1';
}

function parseBoolArray (value) {
  if (!value) return null
  return array.parse(value, parseBool)
}

function parseBaseTenInt (string) {
  return parseInt(string, 10)
}

function parseIntegerArray (value) {
  if (!value) return null
  return array.parse(value, allowNull(parseBaseTenInt))
}

function parseBigIntegerArray (value) {
  if (!value) return null
  return array.parse(value, allowNull(function (entry) {
    return parseBigInteger(entry).trim()
  }))
}

var parsePointArray = function(value) {
  if(!value) { return null; }
  var p = arrayParser.create(value, function(entry) {
    if(entry !== null) {
      entry = parsePoint(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseFloatArray = function(value) {
  if(!value) { return null; }
  var p = arrayParser.create(value, function(entry) {
    if(entry !== null) {
      entry = parseFloat(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseStringArray = function(value) {
  if(!value) { return null; }

  var p = arrayParser.create(value);
  return p.parse();
};

var parseDateArray = function(value) {
  if (!value) { return null; }

  var p = arrayParser.create(value, function(entry) {
    if (entry !== null) {
      entry = parseDate(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseByteAArray = function(value) {
  if (!value) { return null; }

  return array.parse(value, allowNull(parseByteA));
};

var parseInteger = function(value) {
  return parseInt(value, 10);
};

var parseBigInteger = function(value) {
  var valStr = String(value);
  if (/^\d+$/.test(valStr)) { return valStr; }
  return value;
};

var parseJsonArray = function(value) {
  var arr = parseStringArray(value);

  if (!arr) {
    return arr;
  }

  return arr.map(function(el) { return JSON.parse(el); });
};

var parsePoint = function(value) {
  if (value[0] !== '(') { return null; }

  value = value.substring( 1, value.length - 1 ).split(',');

  return {
    x: parseFloat(value[0])
  , y: parseFloat(value[1])
  };
};

var parseCircle = function(value) {
  if (value[0] !== '<' && value[1] !== '(') { return null; }

  var point = '(';
  var radius = '';
  var pointParsed = false;
  for (var i = 2; i < value.length - 1; i++){
    if (!pointParsed) {
      point += value[i];
    }

    if (value[i] === ')') {
      pointParsed = true;
      continue;
    } else if (!pointParsed) {
      continue;
    }

    if (value[i] === ','){
      continue;
    }

    radius += value[i];
  }
  var result = parsePoint(point);
  result.radius = parseFloat(radius);

  return result;
};

var init = function(register) {
  register(20, parseBigInteger); // int8
  register(21, parseInteger); // int2
  register(23, parseInteger); // int4
  register(26, parseInteger); // oid
  register(700, parseFloat); // float4/real
  register(701, parseFloat); // float8/double
  register(16, parseBool);
  register(1082, parseDate); // date
  register(1114, parseDate); // timestamp without timezone
  register(1184, parseDate); // timestamp
  register(600, parsePoint); // point
  register(651, parseStringArray); // cidr[]
  register(718, parseCircle); // circle
  register(1000, parseBoolArray);
  register(1001, parseByteAArray);
  register(1005, parseIntegerArray); // _int2
  register(1007, parseIntegerArray); // _int4
  register(1028, parseIntegerArray); // oid[]
  register(1016, parseBigIntegerArray); // _int8
  register(1017, parsePointArray); // point[]
  register(1021, parseFloatArray); // _float4
  register(1022, parseFloatArray); // _float8
  register(1231, parseFloatArray); // _numeric
  register(1014, parseStringArray); //char
  register(1015, parseStringArray); //varchar
  register(1008, parseStringArray);
  register(1009, parseStringArray);
  register(1040, parseStringArray); // macaddr[]
  register(1041, parseStringArray); // inet[]
  register(1115, parseDateArray); // timestamp without time zone[]
  register(1182, parseDateArray); // _date
  register(1185, parseDateArray); // timestamp with time zone[]
  register(1186, parseInterval);
  register(17, parseByteA);
  register(114, JSON.parse.bind(JSON)); // json
  register(3802, JSON.parse.bind(JSON)); // jsonb
  register(199, parseJsonArray); // json[]
  register(3807, parseJsonArray); // jsonb[]
  register(3907, parseStringArray); // numrange[]
  register(2951, parseStringArray); // uuid[]
  register(791, parseStringArray); // money[]
  register(1183, parseStringArray); // time[]
  register(1270, parseStringArray); // timetz[]
};

module.exports = {
  init: init
};

},
"bEvcYhHaxxrPXXLYZoF6lPQ4EFQKsNkipsl/yeEz1oM=":
function (require, module, exports, __dirname, __filename) {
var Libpq = require('libpq')
var EventEmitter = require('events').EventEmitter
var util = require('util')
var assert = require('assert')
var types = require('pg-types')
var buildResult = require('./lib/build-result')
var CopyStream = require('./lib/copy-stream')

var Client = module.exports = function (config) {
  if (!(this instanceof Client)) {
    return new Client(config)
  }

  config = config || {}

  EventEmitter.call(this)
  this.pq = new Libpq()
  this._reading = false
  this._read = this._read.bind(this)

  // allow custom type converstion to be passed in
  this._types = config.types || types

  // allow config to specify returning results
  // as an array of values instead of a hash
  this.arrayMode = config.arrayMode || false
  this._resultCount = 0
  this._rows = undefined
  this._results = undefined

  // lazy start the reader if notifications are listened for
  // this way if you only run sync queries you wont block
  // the event loop artificially
  this.on('newListener', (event) => {
    if (event !== 'notification') return
    this._startReading()
  })

  this.on('result', this._onResult.bind(this))
  this.on('readyForQuery', this._onReadyForQuery.bind(this))
}

util.inherits(Client, EventEmitter)

Client.prototype.connect = function (params, cb) {
  this.pq.connect(params, cb)
}

Client.prototype.connectSync = function (params) {
  this.pq.connectSync(params)
}

Client.prototype.query = function (text, values, cb) {
  var queryFn

  if (typeof values === 'function') {
    cb = values
    queryFn = function () { return self.pq.sendQuery(text) }
  } else {
    queryFn = function () { return self.pq.sendQueryParams(text, values) }
  }

  var self = this

  self._dispatchQuery(self.pq, queryFn, function (err) {
    if (err) return cb(err)

    self._awaitResult(cb)
  })
}

Client.prototype.prepare = function (statementName, text, nParams, cb) {
  var self = this
  var fn = function () {
    return self.pq.sendPrepare(statementName, text, nParams)
  }

  self._dispatchQuery(self.pq, fn, function (err) {
    if (err) return cb(err)
    self._awaitResult(cb)
  })
}

Client.prototype.execute = function (statementName, parameters, cb) {
  var self = this

  var fn = function () {
    return self.pq.sendQueryPrepared(statementName, parameters)
  }

  self._dispatchQuery(self.pq, fn, function (err, rows) {
    if (err) return cb(err)
    self._awaitResult(cb)
  })
}

Client.prototype.getCopyStream = function () {
  this.pq.setNonBlocking(true)
  this._stopReading()
  return new CopyStream(this.pq)
}

// cancel a currently executing query
Client.prototype.cancel = function (cb) {
  assert(cb, 'Callback is required')
  // result is either true or a string containing an error
  var result = this.pq.cancel()
  return setImmediate(function () {
    cb(result === true ? undefined : new Error(result))
  })
}

Client.prototype.querySync = function (text, values) {
  if (values) {
    this.pq.execParams(text, values)
  } else {
    this.pq.exec(text)
  }

  throwIfError(this.pq)
  const result = buildResult(this.pq, this._types, this.arrayMode)
  return result.rows
}

Client.prototype.prepareSync = function (statementName, text, nParams) {
  this.pq.prepare(statementName, text, nParams)
  throwIfError(this.pq)
}

Client.prototype.executeSync = function (statementName, parameters) {
  this.pq.execPrepared(statementName, parameters)
  throwIfError(this.pq)
  return buildResult(this.pq, this._types, this.arrayMode).rows
}

Client.prototype.escapeLiteral = function (value) {
  return this.pq.escapeLiteral(value)
}

Client.prototype.escapeIdentifier = function (value) {
  return this.pq.escapeIdentifier(value)
}

// export the version number so we can check it in node-postgres
module.exports.version = require('./package.json').version

Client.prototype.end = function (cb) {
  this._stopReading()
  this.pq.finish()
  if (cb) setImmediate(cb)
}

Client.prototype._readError = function (message) {
  var err = new Error(message || this.pq.errorMessage())
  this.emit('error', err)
}

Client.prototype._stopReading = function () {
  if (!this._reading) return
  this._reading = false
  this.pq.stopReader()
  this.pq.removeListener('readable', this._read)
}

Client.prototype._consumeQueryResults = function (pq) {
  return buildResult(pq, this._types, this.arrayMode)
}

Client.prototype._emitResult = function (pq) {
  var status = pq.resultStatus()
  switch (status) {
    case 'PGRES_FATAL_ERROR':
      this._queryError = new Error(this.pq.resultErrorMessage())
      break

    case 'PGRES_TUPLES_OK':
    case 'PGRES_COMMAND_OK':
    case 'PGRES_EMPTY_QUERY':
      const result = this._consumeQueryResults(this.pq)
      this.emit('result', result)
      break

    case 'PGRES_COPY_OUT':
    case 'PGRES_COPY_BOTH': {
      break
    }

    default:
      this._readError('unrecognized command status: ' + status)
      break
  }
  return status
}

// called when libpq is readable
Client.prototype._read = function () {
  var pq = this.pq
  // read waiting data from the socket
  // e.g. clear the pending 'select'
  if (!pq.consumeInput()) {
    // if consumeInput returns false
    // than a read error has been encountered
    return this._readError()
  }

  // check if there is still outstanding data
  // if so, wait for it all to come in
  if (pq.isBusy()) {
    return
  }

  // load our result object

  while (pq.getResult()) {
    const resultStatus = this._emitResult(this.pq)

    // if the command initiated copy mode we need to break out of the read loop
    // so a substream can begin to read copy data
    if (resultStatus === 'PGRES_COPY_BOTH' || resultStatus === 'PGRES_COPY_OUT') {
      break
    }

    // if reading multiple results, sometimes the following results might cause
    // a blocking read. in this scenario yield back off the reader until libpq is readable
    if (pq.isBusy()) {
      return
    }
  }

  this.emit('readyForQuery')

  var notice = this.pq.notifies()
  while (notice) {
    this.emit('notification', notice)
    notice = this.pq.notifies()
  }
}

// ensures the client is reading and
// everything is set up for async io
Client.prototype._startReading = function () {
  if (this._reading) return
  this._reading = true
  this.pq.on('readable', this._read)
  this.pq.startReader()
}

var throwIfError = function (pq) {
  var err = pq.resultErrorMessage() || pq.errorMessage()
  if (err) {
    throw new Error(err)
  }
}

Client.prototype._awaitResult = function (cb) {
  this._queryCallback = cb
  return this._startReading()
}

// wait for the writable socket to drain
Client.prototype._waitForDrain = function (pq, cb) {
  var res = pq.flush()
  // res of 0 is success
  if (res === 0) return cb()

  // res of -1 is failure
  if (res === -1) return cb(pq.errorMessage())

  // otherwise outgoing message didn't flush to socket
  // wait for it to flush and try again
  var self = this
  // you cannot read & write on a socket at the same time
  return pq.writable(function () {
    self._waitForDrain(pq, cb)
  })
}

// send an async query to libpq and wait for it to
// finish writing query text to the socket
Client.prototype._dispatchQuery = function (pq, fn, cb) {
  this._stopReading()
  var success = pq.setNonBlocking(true)
  if (!success) return cb(new Error('Unable to set non-blocking to true'))
  var sent = fn()
  if (!sent) return cb(new Error(pq.errorMessage() || 'Something went wrong dispatching the query'))
  this._waitForDrain(pq, cb)
}

Client.prototype._onResult = function (result) {
  if (this._resultCount === 0) {
    this._results = result
    this._rows = result.rows
  } else if (this._resultCount === 1) {
    this._results = [this._results, result]
    this._rows = [this._rows, result.rows]
  } else {
    this._results.push(result)
    this._rows.push(result.rows)
  }
  this._resultCount++
}

Client.prototype._onReadyForQuery = function () {
  // remove instance callback
  const cb = this._queryCallback
  this._queryCallback = undefined

  // remove instance query error
  const err = this._queryError
  this._queryError = undefined

  // remove instance rows
  const rows = this._rows
  this._rows = undefined

  // remove instance results
  const results = this._results
  this._results = undefined

  this._resultCount = 0

  if (cb) {
    cb(err, rows || [], results)
  }
}

},
"bQ727hJ1DdQaysD8qOUgzwZmmLRW4wYnGC64g6zfyUA=":
function (require, module, exports, __dirname, __filename) {
"use strict";
//binary data writer tuned for encoding binary specific to the postgres binary protocol
Object.defineProperty(exports, "__esModule", { value: true });
class Writer {
    constructor(size = 256) {
        this.size = size;
        this.offset = 5;
        this.headerPosition = 0;
        this.buffer = Buffer.alloc(size);
    }
    ensure(size) {
        var remaining = this.buffer.length - this.offset;
        if (remaining < size) {
            var oldBuffer = this.buffer;
            // exponential growth factor of around ~ 1.5
            // https://stackoverflow.com/questions/2269063/buffer-growth-strategy
            var newSize = oldBuffer.length + (oldBuffer.length >> 1) + size;
            this.buffer = Buffer.alloc(newSize);
            oldBuffer.copy(this.buffer);
        }
    }
    addInt32(num) {
        this.ensure(4);
        this.buffer[this.offset++] = (num >>> 24) & 0xff;
        this.buffer[this.offset++] = (num >>> 16) & 0xff;
        this.buffer[this.offset++] = (num >>> 8) & 0xff;
        this.buffer[this.offset++] = (num >>> 0) & 0xff;
        return this;
    }
    addInt16(num) {
        this.ensure(2);
        this.buffer[this.offset++] = (num >>> 8) & 0xff;
        this.buffer[this.offset++] = (num >>> 0) & 0xff;
        return this;
    }
    addCString(string) {
        if (!string) {
            this.ensure(1);
        }
        else {
            var len = Buffer.byteLength(string);
            this.ensure(len + 1); // +1 for null terminator
            this.buffer.write(string, this.offset, 'utf-8');
            this.offset += len;
        }
        this.buffer[this.offset++] = 0; // null terminator
        return this;
    }
    addString(string = '') {
        var len = Buffer.byteLength(string);
        this.ensure(len);
        this.buffer.write(string, this.offset);
        this.offset += len;
        return this;
    }
    add(otherBuffer) {
        this.ensure(otherBuffer.length);
        otherBuffer.copy(this.buffer, this.offset);
        this.offset += otherBuffer.length;
        return this;
    }
    join(code) {
        if (code) {
            this.buffer[this.headerPosition] = code;
            //length is everything in this packet minus the code
            const length = this.offset - (this.headerPosition + 1);
            this.buffer.writeInt32BE(length, this.headerPosition + 1);
        }
        return this.buffer.slice(code ? 0 : 5, this.offset);
    }
    flush(code) {
        var result = this.join(code);
        this.offset = 5;
        this.headerPosition = 0;
        this.buffer = Buffer.allocUnsafe(this.size);
        return result;
    }
}
exports.Writer = Writer;
//# sourceMappingURL=buffer-writer.js.map
},
"caOGScd0CCF0g/gfVdruHWZG1sZw49A0pEgss0U4huk=":
function (require, module, exports, __dirname, __filename) {
module.exports = extend

var hasOwnProperty = Object.prototype.hasOwnProperty;

function extend(target) {
    for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i]

        for (var key in source) {
            if (hasOwnProperty.call(source, key)) {
                target[key] = source[key]
            }
        }
    }

    return target
}

},
"dEm6mZ1Ft7Wp+LxXZ4tBQ9lKGyzKvYRWqaIWPrWvDus=":
function (require, module, exports, __dirname, __filename) {
//filter will reemit the data if cb(err,pass) pass is truthy

// reduce is more tricky
// maybe we want to group the reductions or emit progress updates occasionally
// the most basic reduce just emits one 'data' event after it has recieved 'end'


var through = require('through')
var Decoder = require('string_decoder').StringDecoder

module.exports = split

//TODO pass in a function to map across the lines.

function split (matcher, mapper, options) {
  var decoder = new Decoder()
  var soFar = ''
  var maxLength = options && options.maxLength;
  var trailing = options && options.trailing === false ? false : true
  if('function' === typeof matcher)
    mapper = matcher, matcher = null
  if (!matcher)
    matcher = /\r?\n/

  function emit(stream, piece) {
    if(mapper) {
      try {
        piece = mapper(piece)
      }
      catch (err) {
        return stream.emit('error', err)
      }
      if('undefined' !== typeof piece)
        stream.queue(piece)
    }
    else
      stream.queue(piece)
  }

  function next (stream, buffer) {
    var pieces = ((soFar != null ? soFar : '') + buffer).split(matcher)
    soFar = pieces.pop()

    if (maxLength && soFar.length > maxLength)
      return stream.emit('error', new Error('maximum buffer reached'))

    for (var i = 0; i < pieces.length; i++) {
      var piece = pieces[i]
      emit(stream, piece)
    }
  }

  return through(function (b) {
    next(this, decoder.write(b))
  },
  function () {
    if(decoder.end)
      next(this, decoder.end())
    if(trailing && soFar != null)
      emit(this, soFar)
    this.queue(null)
  })
}

},
"dYwHlwmLA9EUU1C8Lnbov7Mjg0HCCuvpeSqcpaPpnTY=":
function (require, module, exports, __dirname, __filename) {
'use strict'

var url = require('url')
var fs = require('fs')

//Parse method copied from https://github.com/brianc/node-postgres
//Copyright (c) 2010-2014 Brian Carlson (brian.m.carlson@gmail.com)
//MIT License

//parses a connection string
function parse(str) {
  //unix socket
  if (str.charAt(0) === '/') {
    var config = str.split(' ')
    return { host: config[0], database: config[1] }
  }

  // url parse expects spaces encoded as %20
  var result = url.parse(
    / |%[^a-f0-9]|%[a-f0-9][^a-f0-9]/i.test(str) ? encodeURI(str).replace(/\%25(\d\d)/g, '%$1') : str,
    true
  )
  var config = result.query
  for (var k in config) {
    if (Array.isArray(config[k])) {
      config[k] = config[k][config[k].length - 1]
    }
  }

  var auth = (result.auth || ':').split(':')
  config.user = auth[0]
  config.password = auth.splice(1).join(':')

  config.port = result.port
  if (result.protocol == 'socket:') {
    config.host = decodeURI(result.pathname)
    config.database = result.query.db
    config.client_encoding = result.query.encoding
    return config
  }
  if (!config.host) {
    // Only set the host if there is no equivalent query param.
    config.host = result.hostname
  }

  // If the host is missing it might be a URL-encoded path to a socket.
  var pathname = result.pathname
  if (!config.host && pathname && /^%2f/i.test(pathname)) {
    var pathnameSplit = pathname.split('/')
    config.host = decodeURIComponent(pathnameSplit[0])
    pathname = pathnameSplit.splice(1).join('/')
  }
  // result.pathname is not always guaranteed to have a '/' prefix (e.g. relative urls)
  // only strip the slash if it is present.
  if (pathname && pathname.charAt(0) === '/') {
    pathname = pathname.slice(1) || null
  }
  config.database = pathname && decodeURI(pathname)

  if (config.ssl === 'true' || config.ssl === '1') {
    config.ssl = true
  }

  if (config.ssl === '0') {
    config.ssl = false
  }

  if (config.sslcert || config.sslkey || config.sslrootcert) {
    config.ssl = {}
  }

  if (config.sslcert) {
    config.ssl.cert = fs.readFileSync(config.sslcert).toString()
  }

  if (config.sslkey) {
    config.ssl.key = fs.readFileSync(config.sslkey).toString()
  }

  if (config.sslrootcert) {
    config.ssl.ca = fs.readFileSync(config.sslrootcert).toString()
  }

  return config
}

module.exports = parse

parse.parse = parse

},
"dgEfrtkgzKNgI6IwktnAP+4Fi6Fd2e5Zy9aD0dXaU3c=":
function (require, module, exports, __dirname, __filename) {
'use strict'
const EventEmitter = require('events').EventEmitter

const NOOP = function () {}

const removeWhere = (list, predicate) => {
  const i = list.findIndex(predicate)

  return i === -1 ? undefined : list.splice(i, 1)[0]
}

class IdleItem {
  constructor(client, idleListener, timeoutId) {
    this.client = client
    this.idleListener = idleListener
    this.timeoutId = timeoutId
  }
}

class PendingItem {
  constructor(callback) {
    this.callback = callback
  }
}

function throwOnDoubleRelease() {
  throw new Error('Release called on client which has already been released to the pool.')
}

function promisify(Promise, callback) {
  if (callback) {
    return { callback: callback, result: undefined }
  }
  let rej
  let res
  const cb = function (err, client) {
    err ? rej(err) : res(client)
  }
  const result = new Promise(function (resolve, reject) {
    res = resolve
    rej = reject
  })
  return { callback: cb, result: result }
}

function makeIdleListener(pool, client) {
  return function idleListener(err) {
    err.client = client

    client.removeListener('error', idleListener)
    client.on('error', () => {
      pool.log('additional client error after disconnection due to error', err)
    })
    pool._remove(client)
    // TODO - document that once the pool emits an error
    // the client has already been closed & purged and is unusable
    pool.emit('error', err, client)
  }
}

class Pool extends EventEmitter {
  constructor(options, Client) {
    super()
    this.options = Object.assign({}, options)

    if (options != null && 'password' in options) {
      // "hiding" the password so it doesn't show up in stack traces
      // or if the client is console.logged
      Object.defineProperty(this.options, 'password', {
        configurable: true,
        enumerable: false,
        writable: true,
        value: options.password,
      })
    }

    this.options.max = this.options.max || this.options.poolSize || 10
    this.options.maxUses = this.options.maxUses || Infinity
    this.log = this.options.log || function () {}
    this.Client = this.options.Client || Client || require('pg').Client
    this.Promise = this.options.Promise || global.Promise

    if (typeof this.options.idleTimeoutMillis === 'undefined') {
      this.options.idleTimeoutMillis = 10000
    }

    this._clients = []
    this._idle = []
    this._pendingQueue = []
    this._endCallback = undefined
    this.ending = false
    this.ended = false
  }

  _isFull() {
    return this._clients.length >= this.options.max
  }

  _pulseQueue() {
    this.log('pulse queue')
    if (this.ended) {
      this.log('pulse queue ended')
      return
    }
    if (this.ending) {
      this.log('pulse queue on ending')
      if (this._idle.length) {
        this._idle.slice().map((item) => {
          this._remove(item.client)
        })
      }
      if (!this._clients.length) {
        this.ended = true
        this._endCallback()
      }
      return
    }
    // if we don't have any waiting, do nothing
    if (!this._pendingQueue.length) {
      this.log('no queued requests')
      return
    }
    // if we don't have any idle clients and we have no more room do nothing
    if (!this._idle.length && this._isFull()) {
      return
    }
    const pendingItem = this._pendingQueue.shift()
    if (this._idle.length) {
      const idleItem = this._idle.pop()
      clearTimeout(idleItem.timeoutId)
      const client = idleItem.client
      const idleListener = idleItem.idleListener

      return this._acquireClient(client, pendingItem, idleListener, false)
    }
    if (!this._isFull()) {
      return this.newClient(pendingItem)
    }
    throw new Error('unexpected condition')
  }

  _remove(client) {
    const removed = removeWhere(this._idle, (item) => item.client === client)

    if (removed !== undefined) {
      clearTimeout(removed.timeoutId)
    }

    this._clients = this._clients.filter((c) => c !== client)
    client.end()
    this.emit('remove', client)
  }

  connect(cb) {
    if (this.ending) {
      const err = new Error('Cannot use a pool after calling end on the pool')
      return cb ? cb(err) : this.Promise.reject(err)
    }

    const response = promisify(this.Promise, cb)
    const result = response.result

    // if we don't have to connect a new client, don't do so
    if (this._clients.length >= this.options.max || this._idle.length) {
      // if we have idle clients schedule a pulse immediately
      if (this._idle.length) {
        process.nextTick(() => this._pulseQueue())
      }

      if (!this.options.connectionTimeoutMillis) {
        this._pendingQueue.push(new PendingItem(response.callback))
        return result
      }

      const queueCallback = (err, res, done) => {
        clearTimeout(tid)
        response.callback(err, res, done)
      }

      const pendingItem = new PendingItem(queueCallback)

      // set connection timeout on checking out an existing client
      const tid = setTimeout(() => {
        // remove the callback from pending waiters because
        // we're going to call it with a timeout error
        removeWhere(this._pendingQueue, (i) => i.callback === queueCallback)
        pendingItem.timedOut = true
        response.callback(new Error('timeout exceeded when trying to connect'))
      }, this.options.connectionTimeoutMillis)

      this._pendingQueue.push(pendingItem)
      return result
    }

    this.newClient(new PendingItem(response.callback))

    return result
  }

  newClient(pendingItem) {
    const client = new this.Client(this.options)
    this._clients.push(client)
    const idleListener = makeIdleListener(this, client)

    this.log('checking client timeout')

    // connection timeout logic
    let tid
    let timeoutHit = false
    if (this.options.connectionTimeoutMillis) {
      tid = setTimeout(() => {
        this.log('ending client due to timeout')
        timeoutHit = true
        // force kill the node driver, and let libpq do its teardown
        client.connection ? client.connection.stream.destroy() : client.end()
      }, this.options.connectionTimeoutMillis)
    }

    this.log('connecting new client')
    client.connect((err) => {
      if (tid) {
        clearTimeout(tid)
      }
      client.on('error', idleListener)
      if (err) {
        this.log('client failed to connect', err)
        // remove the dead client from our list of clients
        this._clients = this._clients.filter((c) => c !== client)
        if (timeoutHit) {
          err.message = 'Connection terminated due to connection timeout'
        }

        // this client won’t be released, so move on immediately
        this._pulseQueue()

        if (!pendingItem.timedOut) {
          pendingItem.callback(err, undefined, NOOP)
        }
      } else {
        this.log('new client connected')

        return this._acquireClient(client, pendingItem, idleListener, true)
      }
    })
  }

  // acquire a client for a pending work item
  _acquireClient(client, pendingItem, idleListener, isNew) {
    if (isNew) {
      this.emit('connect', client)
    }

    this.emit('acquire', client)

    client.release = this._releaseOnce(client, idleListener)

    client.removeListener('error', idleListener)

    if (!pendingItem.timedOut) {
      if (isNew && this.options.verify) {
        this.options.verify(client, (err) => {
          if (err) {
            client.release(err)
            return pendingItem.callback(err, undefined, NOOP)
          }

          pendingItem.callback(undefined, client, client.release)
        })
      } else {
        pendingItem.callback(undefined, client, client.release)
      }
    } else {
      if (isNew && this.options.verify) {
        this.options.verify(client, client.release)
      } else {
        client.release()
      }
    }
  }

  // returns a function that wraps _release and throws if called more than once
  _releaseOnce(client, idleListener) {
    let released = false

    return (err) => {
      if (released) {
        throwOnDoubleRelease()
      }

      released = true
      this._release(client, idleListener, err)
    }
  }

  // release a client back to the poll, include an error
  // to remove it from the pool
  _release(client, idleListener, err) {
    client.on('error', idleListener)

    client._poolUseCount = (client._poolUseCount || 0) + 1

    // TODO(bmc): expose a proper, public interface _queryable and _ending
    if (err || this.ending || !client._queryable || client._ending || client._poolUseCount >= this.options.maxUses) {
      if (client._poolUseCount >= this.options.maxUses) {
        this.log('remove expended client')
      }
      this._remove(client)
      this._pulseQueue()
      return
    }

    // idle timeout
    let tid
    if (this.options.idleTimeoutMillis) {
      tid = setTimeout(() => {
        this.log('remove idle client')
        this._remove(client)
      }, this.options.idleTimeoutMillis)
    }

    this._idle.push(new IdleItem(client, idleListener, tid))
    this._pulseQueue()
  }

  query(text, values, cb) {
    // guard clause against passing a function as the first parameter
    if (typeof text === 'function') {
      const response = promisify(this.Promise, text)
      setImmediate(function () {
        return response.callback(new Error('Passing a function as the first parameter to pool.query is not supported'))
      })
      return response.result
    }

    // allow plain text query without values
    if (typeof values === 'function') {
      cb = values
      values = undefined
    }
    const response = promisify(this.Promise, cb)
    cb = response.callback

    this.connect((err, client) => {
      if (err) {
        return cb(err)
      }

      let clientReleased = false
      const onError = (err) => {
        if (clientReleased) {
          return
        }
        clientReleased = true
        client.release(err)
        cb(err)
      }

      client.once('error', onError)
      this.log('dispatching query')
      client.query(text, values, (err, res) => {
        this.log('query dispatched')
        client.removeListener('error', onError)
        if (clientReleased) {
          return
        }
        clientReleased = true
        client.release(err)
        if (err) {
          return cb(err)
        } else {
          return cb(undefined, res)
        }
      })
    })
    return response.result
  }

  end(cb) {
    this.log('ending')
    if (this.ending) {
      const err = new Error('Called end on pool more than once')
      return cb ? cb(err) : this.Promise.reject(err)
    }
    this.ending = true
    const promised = promisify(this.Promise, cb)
    this._endCallback = promised.callback
    this._pulseQueue()
    return promised.result
  }

  get waitingCount() {
    return this._pendingQueue.length
  }

  get idleCount() {
    return this._idle.length
  }

  get totalCount() {
    return this._clients.length
  }
}
module.exports = Pool

},
"exLo+LL6iEtcMQDRgCxeR5HkEQnrj5TbqHESoitLZgg=":
function (require, module, exports, __dirname, __filename) {
// Generated by purs bundle 0.13.8
var PS = {};
(function(exports) {
  /* global XMLHttpRequest */
  /* global process */
  "use strict";

  exports._ajax = function () {
    var platformSpecific = { };
    if (typeof module !== "undefined" && module.require && !(typeof process !== "undefined" && process.versions["electron"])) {
      // We are on node.js
      platformSpecific.newXHR = function () {
        var XHR = module.require("xhr2");
        return new XHR();
      };

      platformSpecific.fixupUrl = function (url, xhr) {
        if (xhr.nodejsBaseUrl === null) {
          var urllib = module.require("url");
          var u = urllib.parse(url);
          u.protocol = u.protocol || "http:";
          u.hostname = u.hostname || "localhost";
          return urllib.format(u);
        } else {
          return url || "/";
        }
      };

      platformSpecific.getResponse = function (xhr) {
        return xhr.response;
      };
    } else {
      // We are in the browser
      platformSpecific.newXHR = function () {
        return new XMLHttpRequest();
      };

      platformSpecific.fixupUrl = function (url) {
        return url || "/";
      };

      platformSpecific.getResponse = function (xhr) {
        return xhr.response;
      };
    }

    return function (mkHeader, options) {
      return function (errback, callback) {
        var xhr = platformSpecific.newXHR();
        var fixedUrl = platformSpecific.fixupUrl(options.url, xhr);
        xhr.open(options.method || "GET", fixedUrl, true, options.username, options.password);
        if (options.headers) {
          try {
            for (var i = 0, header; (header = options.headers[i]) != null; i++) {
              xhr.setRequestHeader(header.field, header.value);
            }
          } catch (e) {
            errback(e);
          }
        }
        var onerror = function (msg) {
          return function () {
            errback(new Error(msg + ": " + options.method + " " + options.url));
          };
        };
        xhr.onerror = onerror("AJAX request failed");
        xhr.ontimeout = onerror("AJAX request timed out");
        xhr.onload = function () {
          callback({
            status: xhr.status,
            statusText: xhr.statusText,
            headers: xhr.getAllResponseHeaders().split("\r\n")
              .filter(function (header) {
                return header.length > 0;
              })
              .map(function (header) {
                var i = header.indexOf(":");
                return mkHeader(header.substring(0, i))(header.substring(i + 2));
              }),
            body: platformSpecific.getResponse(xhr)
          });
        };
        xhr.responseType = options.responseType;
        xhr.withCredentials = options.withCredentials;
        xhr.send(options.content);

        return function (error, cancelErrback, cancelCallback) {
          try {
            xhr.abort();
          } catch (e) {
            return cancelErrback(e);
          }
          return cancelCallback();
        };
      };
    };
  }();
})(PS["Affjax"] = PS["Affjax"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Semigroupoid"] = $PS["Control.Semigroupoid"] || {};
  var exports = $PS["Control.Semigroupoid"];
  var Semigroupoid = function (compose) {
      this.compose = compose;
  };
  var semigroupoidFn = new Semigroupoid(function (f) {
      return function (g) {
          return function (x) {
              return f(g(x));
          };
      };
  });
  var compose = function (dict) {
      return dict.compose;
  };
  var composeFlipped = function (dictSemigroupoid) {
      return function (f) {
          return function (g) {
              return compose(dictSemigroupoid)(g)(f);
          };
      };
  };
  exports["compose"] = compose;
  exports["Semigroupoid"] = Semigroupoid;
  exports["composeFlipped"] = composeFlipped;
  exports["semigroupoidFn"] = semigroupoidFn;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Category"] = $PS["Control.Category"] || {};
  var exports = $PS["Control.Category"];
  var Control_Semigroupoid = $PS["Control.Semigroupoid"];                
  var Category = function (Semigroupoid0, identity) {
      this.Semigroupoid0 = Semigroupoid0;
      this.identity = identity;
  };
  var identity = function (dict) {
      return dict.identity;
  };
  var categoryFn = new Category(function () {
      return Control_Semigroupoid.semigroupoidFn;
  }, function (x) {
      return x;
  });
  exports["identity"] = identity;
  exports["categoryFn"] = categoryFn;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Function"] = $PS["Data.Function"] || {};
  var exports = $PS["Data.Function"];                    
  var on = function (f) {
      return function (g) {
          return function (x) {
              return function (y) {
                  return f(g(x))(g(y));
              };
          };
      };
  };
  var flip = function (f) {
      return function (b) {
          return function (a) {
              return f(a)(b);
          };
      };
  };
  var $$const = function (a) {
      return function (v) {
          return a;
      };
  };
  var applyFlipped = function (x) {
      return function (f) {
          return f(x);
      };
  };
  exports["flip"] = flip;
  exports["const"] = $$const;
  exports["applyFlipped"] = applyFlipped;
  exports["on"] = on;
})(PS);
(function(exports) {
  "use strict";

  exports.arrayMap = function (f) {
    return function (arr) {
      var l = arr.length;
      var result = new Array(l);
      for (var i = 0; i < l; i++) {
        result[i] = f(arr[i]);
      }
      return result;
    };
  };
})(PS["Data.Functor"] = PS["Data.Functor"] || {});
(function(exports) {
  "use strict";

  exports.unit = {};
})(PS["Data.Unit"] = PS["Data.Unit"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Unit"] = $PS["Data.Unit"] || {};
  var exports = $PS["Data.Unit"];
  var $foreign = $PS["Data.Unit"];
  exports["unit"] = $foreign.unit;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Functor"] = $PS["Data.Functor"] || {};
  var exports = $PS["Data.Functor"];
  var $foreign = $PS["Data.Functor"];
  var Control_Semigroupoid = $PS["Control.Semigroupoid"];
  var Data_Function = $PS["Data.Function"];
  var Data_Unit = $PS["Data.Unit"];                
  var Functor = function (map) {
      this.map = map;
  };
  var map = function (dict) {
      return dict.map;
  };
  var mapFlipped = function (dictFunctor) {
      return function (fa) {
          return function (f) {
              return map(dictFunctor)(f)(fa);
          };
      };
  };
  var $$void = function (dictFunctor) {
      return map(dictFunctor)(Data_Function["const"](Data_Unit.unit));
  };
  var functorFn = new Functor(Control_Semigroupoid.compose(Control_Semigroupoid.semigroupoidFn));
  var functorArray = new Functor($foreign.arrayMap);
  exports["Functor"] = Functor;
  exports["map"] = map;
  exports["mapFlipped"] = mapFlipped;
  exports["void"] = $$void;
  exports["functorFn"] = functorFn;
  exports["functorArray"] = functorArray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Apply"] = $PS["Control.Apply"] || {};
  var exports = $PS["Control.Apply"];
  var Control_Category = $PS["Control.Category"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];                
  var Apply = function (Functor0, apply) {
      this.Functor0 = Functor0;
      this.apply = apply;
  };                      
  var apply = function (dict) {
      return dict.apply;
  };
  var applyFirst = function (dictApply) {
      return function (a) {
          return function (b) {
              return apply(dictApply)(Data_Functor.map(dictApply.Functor0())(Data_Function["const"])(a))(b);
          };
      };
  };
  var applySecond = function (dictApply) {
      return function (a) {
          return function (b) {
              return apply(dictApply)(Data_Functor.map(dictApply.Functor0())(Data_Function["const"](Control_Category.identity(Control_Category.categoryFn)))(a))(b);
          };
      };
  };
  exports["Apply"] = Apply;
  exports["apply"] = apply;
  exports["applyFirst"] = applyFirst;
  exports["applySecond"] = applySecond;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Applicative"] = $PS["Control.Applicative"] || {};
  var exports = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Unit = $PS["Data.Unit"];                
  var Applicative = function (Apply0, pure) {
      this.Apply0 = Apply0;
      this.pure = pure;
  };
  var pure = function (dict) {
      return dict.pure;
  };
  var unless = function (dictApplicative) {
      return function (v) {
          return function (v1) {
              if (!v) {
                  return v1;
              };
              if (v) {
                  return pure(dictApplicative)(Data_Unit.unit);
              };
              throw new Error("Failed pattern match at Control.Applicative (line 62, column 1 - line 62, column 65): " + [ v.constructor.name, v1.constructor.name ]);
          };
      };
  };
  var liftA1 = function (dictApplicative) {
      return function (f) {
          return function (a) {
              return Control_Apply.apply(dictApplicative.Apply0())(pure(dictApplicative)(f))(a);
          };
      };
  };
  exports["Applicative"] = Applicative;
  exports["pure"] = pure;
  exports["liftA1"] = liftA1;
  exports["unless"] = unless;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Bind"] = $PS["Control.Bind"] || {};
  var exports = $PS["Control.Bind"];
  var Control_Category = $PS["Control.Category"];
  var Data_Function = $PS["Data.Function"];                
  var Discard = function (discard) {
      this.discard = discard;
  };
  var Bind = function (Apply0, bind) {
      this.Apply0 = Apply0;
      this.bind = bind;
  };
  var discard = function (dict) {
      return dict.discard;
  };                     
  var bind = function (dict) {
      return dict.bind;
  };
  var bindFlipped = function (dictBind) {
      return Data_Function.flip(bind(dictBind));
  };
  var composeKleisliFlipped = function (dictBind) {
      return function (f) {
          return function (g) {
              return function (a) {
                  return bindFlipped(dictBind)(f)(g(a));
              };
          };
      };
  };
  var discardUnit = new Discard(function (dictBind) {
      return bind(dictBind);
  });
  var join = function (dictBind) {
      return function (m) {
          return bind(dictBind)(m)(Control_Category.identity(Control_Category.categoryFn));
      };
  };
  exports["Bind"] = Bind;
  exports["bind"] = bind;
  exports["bindFlipped"] = bindFlipped;
  exports["discard"] = discard;
  exports["join"] = join;
  exports["composeKleisliFlipped"] = composeKleisliFlipped;
  exports["discardUnit"] = discardUnit;
})(PS);
(function(exports) {
  "use strict";

  exports.showIntImpl = function (n) {
    return n.toString();
  };

  exports.showCharImpl = function (c) {
    var code = c.charCodeAt(0);
    if (code < 0x20 || code === 0x7F) {
      switch (c) {
        case "\x07": return "'\\a'";
        case "\b": return "'\\b'";
        case "\f": return "'\\f'";
        case "\n": return "'\\n'";
        case "\r": return "'\\r'";
        case "\t": return "'\\t'";
        case "\v": return "'\\v'";
      }
      return "'\\" + code.toString(10) + "'";
    }
    return c === "'" || c === "\\" ? "'\\" + c + "'" : "'" + c + "'";
  };

  exports.showStringImpl = function (s) {
    var l = s.length;
    return "\"" + s.replace(
      /[\0-\x1F\x7F"\\]/g, // eslint-disable-line no-control-regex
      function (c, i) {
        switch (c) {
          case "\"":
          case "\\":
            return "\\" + c;
          case "\x07": return "\\a";
          case "\b": return "\\b";
          case "\f": return "\\f";
          case "\n": return "\\n";
          case "\r": return "\\r";
          case "\t": return "\\t";
          case "\v": return "\\v";
        }
        var k = i + 1;
        var empty = k < l && s[k] >= "0" && s[k] <= "9" ? "\\&" : "";
        return "\\" + c.charCodeAt(0).toString(10) + empty;
      }
    ) + "\"";
  };

  exports.showArrayImpl = function (f) {
    return function (xs) {
      var ss = [];
      for (var i = 0, l = xs.length; i < l; i++) {
        ss[i] = f(xs[i]);
      }
      return "[" + ss.join(",") + "]";
    };
  };

  exports.cons = function (head) {
    return function (tail) {
      return [head].concat(tail);
    };
  };

  exports.join = function (separator) {
    return function (xs) {
      return xs.join(separator);
    };
  };
})(PS["Data.Show"] = PS["Data.Show"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Symbol"] = $PS["Data.Symbol"] || {};
  var exports = $PS["Data.Symbol"];      
  var SProxy = (function () {
      function SProxy() {

      };
      SProxy.value = new SProxy();
      return SProxy;
  })();
  var IsSymbol = function (reflectSymbol) {
      this.reflectSymbol = reflectSymbol;
  };
  var reflectSymbol = function (dict) {
      return dict.reflectSymbol;
  };
  exports["IsSymbol"] = IsSymbol;
  exports["reflectSymbol"] = reflectSymbol;
  exports["SProxy"] = SProxy;
})(PS);
(function(exports) {
  "use strict";

  exports.unsafeGet = function (label) {
    return function (rec) {
      return rec[label];
    };
  };

  exports.unsafeSet = function (label) {
    return function (value) {
      return function (rec) {
        var copy = {};
        for (var key in rec) {
          if ({}.hasOwnProperty.call(rec, key)) {
            copy[key] = rec[key];
          }
        }
        copy[label] = value;
        return copy;
      };
    };
  };

  exports.unsafeDelete = function (label) {
    return function (rec) {
      var copy = {};
      for (var key in rec) {
        if (key !== label && {}.hasOwnProperty.call(rec, key)) {
          copy[key] = rec[key];
        }
      }
      return copy;
    };
  };
})(PS["Record.Unsafe"] = PS["Record.Unsafe"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Record.Unsafe"] = $PS["Record.Unsafe"] || {};
  var exports = $PS["Record.Unsafe"];
  var $foreign = $PS["Record.Unsafe"];
  exports["unsafeGet"] = $foreign.unsafeGet;
  exports["unsafeSet"] = $foreign.unsafeSet;
  exports["unsafeDelete"] = $foreign.unsafeDelete;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Type.Data.RowList"] = $PS["Type.Data.RowList"] || {};
  var exports = $PS["Type.Data.RowList"];
  var RLProxy = (function () {
      function RLProxy() {

      };
      RLProxy.value = new RLProxy();
      return RLProxy;
  })();
  exports["RLProxy"] = RLProxy;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Show"] = $PS["Data.Show"] || {};
  var exports = $PS["Data.Show"];
  var $foreign = $PS["Data.Show"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Record_Unsafe = $PS["Record.Unsafe"];
  var Type_Data_RowList = $PS["Type.Data.RowList"];                
  var ShowRecordFields = function (showRecordFields) {
      this.showRecordFields = showRecordFields;
  };
  var Show = function (show) {
      this.show = show;
  };
  var showString = new Show($foreign.showStringImpl);
  var showRecordFieldsNil = new ShowRecordFields(function (v) {
      return function (v1) {
          return [  ];
      };
  });
  var showRecordFields = function (dict) {
      return dict.showRecordFields;
  };
  var showRecord = function (dictRowToList) {
      return function (dictShowRecordFields) {
          return new Show(function (record) {
              var v = showRecordFields(dictShowRecordFields)(Type_Data_RowList.RLProxy.value)(record);
              if (v.length === 0) {
                  return "{}";
              };
              return $foreign.join(" ")([ "{", $foreign.join(", ")(v), "}" ]);
          });
      };
  };                                                 
  var showInt = new Show($foreign.showIntImpl);
  var showChar = new Show($foreign.showCharImpl);
  var show = function (dict) {
      return dict.show;
  };
  var showArray = function (dictShow) {
      return new Show($foreign.showArrayImpl(show(dictShow)));
  };
  var showRecordFieldsCons = function (dictIsSymbol) {
      return function (dictShowRecordFields) {
          return function (dictShow) {
              return new ShowRecordFields(function (v) {
                  return function (record) {
                      var tail = showRecordFields(dictShowRecordFields)(Type_Data_RowList.RLProxy.value)(record);
                      var key = Data_Symbol.reflectSymbol(dictIsSymbol)(Data_Symbol.SProxy.value);
                      var focus = Record_Unsafe.unsafeGet(key)(record);
                      return $foreign.cons($foreign.join(": ")([ key, show(dictShow)(focus) ]))(tail);
                  };
              });
          };
      };
  };
  exports["Show"] = Show;
  exports["show"] = show;
  exports["showInt"] = showInt;
  exports["showChar"] = showChar;
  exports["showString"] = showString;
  exports["showArray"] = showArray;
  exports["showRecord"] = showRecord;
  exports["showRecordFieldsNil"] = showRecordFieldsNil;
  exports["showRecordFieldsCons"] = showRecordFieldsCons;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Maybe"] = $PS["Data.Maybe"] || {};
  var exports = $PS["Data.Maybe"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Category = $PS["Control.Category"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Show = $PS["Data.Show"];                
  var Nothing = (function () {
      function Nothing() {

      };
      Nothing.value = new Nothing();
      return Nothing;
  })();
  var Just = (function () {
      function Just(value0) {
          this.value0 = value0;
      };
      Just.create = function (value0) {
          return new Just(value0);
      };
      return Just;
  })();
  var showMaybe = function (dictShow) {
      return new Data_Show.Show(function (v) {
          if (v instanceof Just) {
              return "(Just " + (Data_Show.show(dictShow)(v.value0) + ")");
          };
          if (v instanceof Nothing) {
              return "Nothing";
          };
          throw new Error("Failed pattern match at Data.Maybe (line 205, column 1 - line 207, column 28): " + [ v.constructor.name ]);
      });
  };
  var maybe = function (v) {
      return function (v1) {
          return function (v2) {
              if (v2 instanceof Nothing) {
                  return v;
              };
              if (v2 instanceof Just) {
                  return v1(v2.value0);
              };
              throw new Error("Failed pattern match at Data.Maybe (line 217, column 1 - line 217, column 51): " + [ v.constructor.name, v1.constructor.name, v2.constructor.name ]);
          };
      };
  };
  var isNothing = maybe(true)(Data_Function["const"](false));
  var isJust = maybe(false)(Data_Function["const"](true));
  var functorMaybe = new Data_Functor.Functor(function (v) {
      return function (v1) {
          if (v1 instanceof Just) {
              return new Just(v(v1.value0));
          };
          return Nothing.value;
      };
  });
  var fromMaybe = function (a) {
      return maybe(a)(Control_Category.identity(Control_Category.categoryFn));
  };
  var fromJust = function (dictPartial) {
      return function (v) {
          if (v instanceof Just) {
              return v.value0;
          };
          throw new Error("Failed pattern match at Data.Maybe (line 268, column 1 - line 268, column 46): " + [ v.constructor.name ]);
      };
  };
  var applyMaybe = new Control_Apply.Apply(function () {
      return functorMaybe;
  }, function (v) {
      return function (v1) {
          if (v instanceof Just) {
              return Data_Functor.map(functorMaybe)(v.value0)(v1);
          };
          if (v instanceof Nothing) {
              return Nothing.value;
          };
          throw new Error("Failed pattern match at Data.Maybe (line 67, column 1 - line 69, column 30): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var bindMaybe = new Control_Bind.Bind(function () {
      return applyMaybe;
  }, function (v) {
      return function (v1) {
          if (v instanceof Just) {
              return v1(v.value0);
          };
          if (v instanceof Nothing) {
              return Nothing.value;
          };
          throw new Error("Failed pattern match at Data.Maybe (line 125, column 1 - line 127, column 28): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var applicativeMaybe = new Control_Applicative.Applicative(function () {
      return applyMaybe;
  }, Just.create);
  exports["Nothing"] = Nothing;
  exports["Just"] = Just;
  exports["maybe"] = maybe;
  exports["fromMaybe"] = fromMaybe;
  exports["isJust"] = isJust;
  exports["isNothing"] = isNothing;
  exports["fromJust"] = fromJust;
  exports["functorMaybe"] = functorMaybe;
  exports["applyMaybe"] = applyMaybe;
  exports["applicativeMaybe"] = applicativeMaybe;
  exports["bindMaybe"] = bindMaybe;
  exports["showMaybe"] = showMaybe;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.MediaType.Common"] = $PS["Data.MediaType.Common"] || {};
  var exports = $PS["Data.MediaType.Common"];          
  var applicationJSON = "application/json";
  var applicationFormURLEncoded = "application/x-www-form-urlencoded";
  exports["applicationFormURLEncoded"] = applicationFormURLEncoded;
  exports["applicationJSON"] = applicationJSON;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Affjax.RequestBody"] = $PS["Affjax.RequestBody"] || {};
  var exports = $PS["Affjax.RequestBody"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_MediaType_Common = $PS["Data.MediaType.Common"];                
  var ArrayView = (function () {
      function ArrayView(value0) {
          this.value0 = value0;
      };
      ArrayView.create = function (value0) {
          return new ArrayView(value0);
      };
      return ArrayView;
  })();
  var Blob = (function () {
      function Blob(value0) {
          this.value0 = value0;
      };
      Blob.create = function (value0) {
          return new Blob(value0);
      };
      return Blob;
  })();
  var Document = (function () {
      function Document(value0) {
          this.value0 = value0;
      };
      Document.create = function (value0) {
          return new Document(value0);
      };
      return Document;
  })();
  var $$String = (function () {
      function $$String(value0) {
          this.value0 = value0;
      };
      $$String.create = function (value0) {
          return new $$String(value0);
      };
      return $$String;
  })();
  var FormData = (function () {
      function FormData(value0) {
          this.value0 = value0;
      };
      FormData.create = function (value0) {
          return new FormData(value0);
      };
      return FormData;
  })();
  var FormURLEncoded = (function () {
      function FormURLEncoded(value0) {
          this.value0 = value0;
      };
      FormURLEncoded.create = function (value0) {
          return new FormURLEncoded(value0);
      };
      return FormURLEncoded;
  })();
  var Json = (function () {
      function Json(value0) {
          this.value0 = value0;
      };
      Json.create = function (value0) {
          return new Json(value0);
      };
      return Json;
  })();
  var toMediaType = function (v) {
      if (v instanceof FormURLEncoded) {
          return new Data_Maybe.Just(Data_MediaType_Common.applicationFormURLEncoded);
      };
      if (v instanceof Json) {
          return new Data_Maybe.Just(Data_MediaType_Common.applicationJSON);
      };
      return Data_Maybe.Nothing.value;
  };                     
  var formURLEncoded = FormURLEncoded.create;
  exports["ArrayView"] = ArrayView;
  exports["Blob"] = Blob;
  exports["Document"] = Document;
  exports["String"] = $$String;
  exports["FormData"] = FormData;
  exports["FormURLEncoded"] = FormURLEncoded;
  exports["Json"] = Json;
  exports["formURLEncoded"] = formURLEncoded;
  exports["toMediaType"] = toMediaType;
})(PS);
(function(exports) {
  "use strict";

  exports.boolConj = function (b1) {
    return function (b2) {
      return b1 && b2;
    };
  };

  exports.boolDisj = function (b1) {
    return function (b2) {
      return b1 || b2;
    };
  };

  exports.boolNot = function (b) {
    return !b;
  };
})(PS["Data.HeytingAlgebra"] = PS["Data.HeytingAlgebra"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.HeytingAlgebra"] = $PS["Data.HeytingAlgebra"] || {};
  var exports = $PS["Data.HeytingAlgebra"];
  var $foreign = $PS["Data.HeytingAlgebra"];
  var HeytingAlgebra = function (conj, disj, ff, implies, not, tt) {
      this.conj = conj;
      this.disj = disj;
      this.ff = ff;
      this.implies = implies;
      this.not = not;
      this.tt = tt;
  };
  var tt = function (dict) {
      return dict.tt;
  };
  var not = function (dict) {
      return dict.not;
  };
  var implies = function (dict) {
      return dict.implies;
  };
  var ff = function (dict) {
      return dict.ff;
  };
  var disj = function (dict) {
      return dict.disj;
  };
  var heytingAlgebraBoolean = new HeytingAlgebra($foreign.boolConj, $foreign.boolDisj, false, function (a) {
      return function (b) {
          return disj(heytingAlgebraBoolean)(not(heytingAlgebraBoolean)(a))(b);
      };
  }, $foreign.boolNot, true);
  var conj = function (dict) {
      return dict.conj;
  };
  var heytingAlgebraFunction = function (dictHeytingAlgebra) {
      return new HeytingAlgebra(function (f) {
          return function (g) {
              return function (a) {
                  return conj(dictHeytingAlgebra)(f(a))(g(a));
              };
          };
      }, function (f) {
          return function (g) {
              return function (a) {
                  return disj(dictHeytingAlgebra)(f(a))(g(a));
              };
          };
      }, function (v) {
          return ff(dictHeytingAlgebra);
      }, function (f) {
          return function (g) {
              return function (a) {
                  return implies(dictHeytingAlgebra)(f(a))(g(a));
              };
          };
      }, function (f) {
          return function (a) {
              return not(dictHeytingAlgebra)(f(a));
          };
      }, function (v) {
          return tt(dictHeytingAlgebra);
      });
  };
  exports["ff"] = ff;
  exports["disj"] = disj;
  exports["not"] = not;
  exports["heytingAlgebraBoolean"] = heytingAlgebraBoolean;
  exports["heytingAlgebraFunction"] = heytingAlgebraFunction;
})(PS);
(function(exports) {
  "use strict";

  exports.concatString = function (s1) {
    return function (s2) {
      return s1 + s2;
    };
  };

  exports.concatArray = function (xs) {
    return function (ys) {
      if (xs.length === 0) return ys;
      if (ys.length === 0) return xs;
      return xs.concat(ys);
    };
  };
})(PS["Data.Semigroup"] = PS["Data.Semigroup"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Semigroup"] = $PS["Data.Semigroup"] || {};
  var exports = $PS["Data.Semigroup"];
  var $foreign = $PS["Data.Semigroup"];
  var Semigroup = function (append) {
      this.append = append;
  }; 
  var semigroupString = new Semigroup($foreign.concatString);
  var semigroupArray = new Semigroup($foreign.concatArray);
  var append = function (dict) {
      return dict.append;
  };
  var semigroupFn = function (dictSemigroup) {
      return new Semigroup(function (f) {
          return function (g) {
              return function (x) {
                  return append(dictSemigroup)(f(x))(g(x));
              };
          };
      });
  };
  exports["Semigroup"] = Semigroup;
  exports["append"] = append;
  exports["semigroupString"] = semigroupString;
  exports["semigroupFn"] = semigroupFn;
  exports["semigroupArray"] = semigroupArray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Monoid"] = $PS["Data.Monoid"] || {};
  var exports = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Monoid = function (Semigroup0, mempty) {
      this.Semigroup0 = Semigroup0;
      this.mempty = mempty;
  };                 
  var monoidString = new Monoid(function () {
      return Data_Semigroup.semigroupString;
  }, "");                    
  var monoidArray = new Monoid(function () {
      return Data_Semigroup.semigroupArray;
  }, [  ]);
  var mempty = function (dict) {
      return dict.mempty;
  };
  var monoidFn = function (dictMonoid) {
      return new Monoid(function () {
          return Data_Semigroup.semigroupFn(dictMonoid.Semigroup0());
      }, function (v) {
          return mempty(dictMonoid);
      });
  };
  exports["Monoid"] = Monoid;
  exports["mempty"] = mempty;
  exports["monoidFn"] = monoidFn;
  exports["monoidString"] = monoidString;
  exports["monoidArray"] = monoidArray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Monoid.Disj"] = $PS["Data.Monoid.Disj"] || {};
  var exports = $PS["Data.Monoid.Disj"];
  var Data_HeytingAlgebra = $PS["Data.HeytingAlgebra"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];      
  var Disj = function (x) {
      return x;
  };
  var semigroupDisj = function (dictHeytingAlgebra) {
      return new Data_Semigroup.Semigroup(function (v) {
          return function (v1) {
              return Data_HeytingAlgebra.disj(dictHeytingAlgebra)(v)(v1);
          };
      });
  };
  var monoidDisj = function (dictHeytingAlgebra) {
      return new Data_Monoid.Monoid(function () {
          return semigroupDisj(dictHeytingAlgebra);
      }, Data_HeytingAlgebra.ff(dictHeytingAlgebra));
  };
  exports["Disj"] = Disj;
  exports["monoidDisj"] = monoidDisj;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Monoid.Endo"] = $PS["Data.Monoid.Endo"] || {};
  var exports = $PS["Data.Monoid.Endo"];
  var Control_Category = $PS["Control.Category"];
  var Control_Semigroupoid = $PS["Control.Semigroupoid"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];      
  var Endo = function (x) {
      return x;
  };
  var semigroupEndo = function (dictSemigroupoid) {
      return new Data_Semigroup.Semigroup(function (v) {
          return function (v1) {
              return Control_Semigroupoid.compose(dictSemigroupoid)(v)(v1);
          };
      });
  };
  var monoidEndo = function (dictCategory) {
      return new Data_Monoid.Monoid(function () {
          return semigroupEndo(dictCategory.Semigroupoid0());
      }, Control_Category.identity(dictCategory));
  };
  exports["Endo"] = Endo;
  exports["monoidEndo"] = monoidEndo;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Newtype"] = $PS["Data.Newtype"] || {};
  var exports = $PS["Data.Newtype"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Monoid_Disj = $PS["Data.Monoid.Disj"];
  var Data_Monoid_Endo = $PS["Data.Monoid.Endo"];                      
  var Newtype = function (unwrap, wrap) {
      this.unwrap = unwrap;
      this.wrap = wrap;
  };
  var wrap = function (dict) {
      return dict.wrap;
  };
  var unwrap = function (dict) {
      return dict.unwrap;
  };
  var under = function (dictNewtype) {
      return function (dictNewtype1) {
          return function (v) {
              return function (f) {
                  var $75 = unwrap(dictNewtype1);
                  var $76 = wrap(dictNewtype);
                  return function ($77) {
                      return $75(f($76($77)));
                  };
              };
          };
      };
  };
  var un = function (dictNewtype) {
      return function (v) {
          return unwrap(dictNewtype);
      };
  };                             
  var newtypeEndo = new Newtype(function (v) {
      return v;
  }, Data_Monoid_Endo.Endo);
  var newtypeDisj = new Newtype(function (v) {
      return v;
  }, Data_Monoid_Disj.Disj);
  var alaF = function (dictFunctor) {
      return function (dictFunctor1) {
          return function (dictNewtype) {
              return function (dictNewtype1) {
                  return function (v) {
                      return function (f) {
                          var $96 = Data_Functor.map(dictFunctor1)(unwrap(dictNewtype1));
                          var $97 = Data_Functor.map(dictFunctor)(wrap(dictNewtype));
                          return function ($98) {
                              return $96(f($97($98)));
                          };
                      };
                  };
              };
          };
      };
  };
  exports["unwrap"] = unwrap;
  exports["wrap"] = wrap;
  exports["Newtype"] = Newtype;
  exports["un"] = un;
  exports["alaF"] = alaF;
  exports["under"] = under;
  exports["newtypeDisj"] = newtypeDisj;
  exports["newtypeEndo"] = newtypeEndo;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.MediaType"] = $PS["Data.MediaType"] || {};
  var exports = $PS["Data.MediaType"];
  var Data_Newtype = $PS["Data.Newtype"];          
  var MediaType = function (x) {
      return x;
  }; 
  var newtypeMediaType = new Data_Newtype.Newtype(function (n) {
      return n;
  }, MediaType);
  exports["newtypeMediaType"] = newtypeMediaType;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Affjax.RequestHeader"] = $PS["Affjax.RequestHeader"] || {};
  var exports = $PS["Affjax.RequestHeader"];
  var Data_MediaType = $PS["Data.MediaType"];
  var Data_Newtype = $PS["Data.Newtype"];          
  var Accept = (function () {
      function Accept(value0) {
          this.value0 = value0;
      };
      Accept.create = function (value0) {
          return new Accept(value0);
      };
      return Accept;
  })();
  var ContentType = (function () {
      function ContentType(value0) {
          this.value0 = value0;
      };
      ContentType.create = function (value0) {
          return new ContentType(value0);
      };
      return ContentType;
  })();
  var RequestHeader = (function () {
      function RequestHeader(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      RequestHeader.create = function (value0) {
          return function (value1) {
              return new RequestHeader(value0, value1);
          };
      };
      return RequestHeader;
  })();
  var value = function (v) {
      if (v instanceof Accept) {
          return Data_Newtype.unwrap(Data_MediaType.newtypeMediaType)(v.value0);
      };
      if (v instanceof ContentType) {
          return Data_Newtype.unwrap(Data_MediaType.newtypeMediaType)(v.value0);
      };
      if (v instanceof RequestHeader) {
          return v.value1;
      };
      throw new Error("Failed pattern match at Affjax.RequestHeader (line 26, column 1 - line 26, column 33): " + [ v.constructor.name ]);
  }; 
  var name = function (v) {
      if (v instanceof Accept) {
          return "Accept";
      };
      if (v instanceof ContentType) {
          return "Content-Type";
      };
      if (v instanceof RequestHeader) {
          return v.value0;
      };
      throw new Error("Failed pattern match at Affjax.RequestHeader (line 21, column 1 - line 21, column 32): " + [ v.constructor.name ]);
  };
  exports["Accept"] = Accept;
  exports["ContentType"] = ContentType;
  exports["name"] = name;
  exports["value"] = value;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Affjax.ResponseFormat"] = $PS["Affjax.ResponseFormat"] || {};
  var exports = $PS["Affjax.ResponseFormat"];
  var Control_Category = $PS["Control.Category"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_MediaType_Common = $PS["Data.MediaType.Common"];                
  var $$ArrayBuffer = (function () {
      function $$ArrayBuffer(value0) {
          this.value0 = value0;
      };
      $$ArrayBuffer.create = function (value0) {
          return new $$ArrayBuffer(value0);
      };
      return $$ArrayBuffer;
  })();
  var Blob = (function () {
      function Blob(value0) {
          this.value0 = value0;
      };
      Blob.create = function (value0) {
          return new Blob(value0);
      };
      return Blob;
  })();
  var Document = (function () {
      function Document(value0) {
          this.value0 = value0;
      };
      Document.create = function (value0) {
          return new Document(value0);
      };
      return Document;
  })();
  var Json = (function () {
      function Json(value0) {
          this.value0 = value0;
      };
      Json.create = function (value0) {
          return new Json(value0);
      };
      return Json;
  })();
  var $$String = (function () {
      function $$String(value0) {
          this.value0 = value0;
      };
      $$String.create = function (value0) {
          return new $$String(value0);
      };
      return $$String;
  })();
  var Ignore = (function () {
      function Ignore(value0) {
          this.value0 = value0;
      };
      Ignore.create = function (value0) {
          return new Ignore(value0);
      };
      return Ignore;
  })();
  var toResponseType = function (v) {
      if (v instanceof $$ArrayBuffer) {
          return "arraybuffer";
      };
      if (v instanceof Blob) {
          return "blob";
      };
      if (v instanceof Document) {
          return "document";
      };
      if (v instanceof Json) {
          return "text";
      };
      if (v instanceof $$String) {
          return "text";
      };
      if (v instanceof Ignore) {
          return "";
      };
      throw new Error("Failed pattern match at Affjax.ResponseFormat (line 44, column 3 - line 50, column 19): " + [ v.constructor.name ]);
  };
  var toMediaType = function (v) {
      if (v instanceof Json) {
          return new Data_Maybe.Just(Data_MediaType_Common.applicationJSON);
      };
      return Data_Maybe.Nothing.value;
  };                                                                                
  var json = new Json(Control_Category.identity(Control_Category.categoryFn));
  var ignore = new Ignore(Control_Category.identity(Control_Category.categoryFn));
  exports["ArrayBuffer"] = $$ArrayBuffer;
  exports["Blob"] = Blob;
  exports["Document"] = Document;
  exports["Json"] = Json;
  exports["String"] = $$String;
  exports["Ignore"] = Ignore;
  exports["json"] = json;
  exports["ignore"] = ignore;
  exports["toResponseType"] = toResponseType;
  exports["toMediaType"] = toMediaType;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Affjax.ResponseHeader"] = $PS["Affjax.ResponseHeader"] || {};
  var exports = $PS["Affjax.ResponseHeader"];      
  var ResponseHeader = (function () {
      function ResponseHeader(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ResponseHeader.create = function (value0) {
          return function (value1) {
              return new ResponseHeader(value0, value1);
          };
      };
      return ResponseHeader;
  })();
  exports["ResponseHeader"] = ResponseHeader;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Bifunctor"] = $PS["Data.Bifunctor"] || {};
  var exports = $PS["Data.Bifunctor"];
  var Control_Category = $PS["Control.Category"];                
  var Bifunctor = function (bimap) {
      this.bimap = bimap;
  };
  var bimap = function (dict) {
      return dict.bimap;
  };
  var lmap = function (dictBifunctor) {
      return function (f) {
          return bimap(dictBifunctor)(f)(Control_Category.identity(Control_Category.categoryFn));
      };
  };
  exports["bimap"] = bimap;
  exports["Bifunctor"] = Bifunctor;
  exports["lmap"] = lmap;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Either"] = $PS["Data.Either"] || {};
  var exports = $PS["Data.Either"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];              
  var Left = (function () {
      function Left(value0) {
          this.value0 = value0;
      };
      Left.create = function (value0) {
          return new Left(value0);
      };
      return Left;
  })();
  var Right = (function () {
      function Right(value0) {
          this.value0 = value0;
      };
      Right.create = function (value0) {
          return new Right(value0);
      };
      return Right;
  })();
  var note = function (a) {
      return Data_Maybe.maybe(new Left(a))(Right.create);
  };
  var functorEither = new Data_Functor.Functor(function (f) {
      return function (m) {
          if (m instanceof Left) {
              return new Left(m.value0);
          };
          if (m instanceof Right) {
              return new Right(f(m.value0));
          };
          throw new Error("Failed pattern match at Data.Either (line 38, column 1 - line 38, column 52): " + [ m.constructor.name ]);
      };
  });
  var either = function (v) {
      return function (v1) {
          return function (v2) {
              if (v2 instanceof Left) {
                  return v(v2.value0);
              };
              if (v2 instanceof Right) {
                  return v1(v2.value0);
              };
              throw new Error("Failed pattern match at Data.Either (line 238, column 1 - line 238, column 64): " + [ v.constructor.name, v1.constructor.name, v2.constructor.name ]);
          };
      };
  };
  var hush = either(Data_Function["const"](Data_Maybe.Nothing.value))(Data_Maybe.Just.create);
  var bifunctorEither = new Data_Bifunctor.Bifunctor(function (v) {
      return function (v1) {
          return function (v2) {
              if (v2 instanceof Left) {
                  return new Left(v(v2.value0));
              };
              if (v2 instanceof Right) {
                  return new Right(v1(v2.value0));
              };
              throw new Error("Failed pattern match at Data.Either (line 46, column 1 - line 48, column 36): " + [ v.constructor.name, v1.constructor.name, v2.constructor.name ]);
          };
      };
  });
  var applyEither = new Control_Apply.Apply(function () {
      return functorEither;
  }, function (v) {
      return function (v1) {
          if (v instanceof Left) {
              return new Left(v.value0);
          };
          if (v instanceof Right) {
              return Data_Functor.map(functorEither)(v.value0)(v1);
          };
          throw new Error("Failed pattern match at Data.Either (line 82, column 1 - line 84, column 30): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var bindEither = new Control_Bind.Bind(function () {
      return applyEither;
  }, either(function (e) {
      return function (v) {
          return new Left(e);
      };
  })(function (a) {
      return function (f) {
          return f(a);
      };
  }));
  var applicativeEither = new Control_Applicative.Applicative(function () {
      return applyEither;
  }, Right.create);
  exports["Left"] = Left;
  exports["Right"] = Right;
  exports["either"] = either;
  exports["note"] = note;
  exports["hush"] = hush;
  exports["functorEither"] = functorEither;
  exports["bifunctorEither"] = bifunctorEither;
  exports["applyEither"] = applyEither;
  exports["applicativeEither"] = applicativeEither;
  exports["bindEither"] = bindEither;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Error.Class"] = $PS["Control.Monad.Error.Class"] || {};
  var exports = $PS["Control.Monad.Error.Class"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];                        
  var MonadThrow = function (Monad0, throwError) {
      this.Monad0 = Monad0;
      this.throwError = throwError;
  };
  var MonadError = function (MonadThrow0, catchError) {
      this.MonadThrow0 = MonadThrow0;
      this.catchError = catchError;
  };
  var throwError = function (dict) {
      return dict.throwError;
  };                                                      
  var catchError = function (dict) {
      return dict.catchError;
  };
  var $$try = function (dictMonadError) {
      return function (a) {
          return catchError(dictMonadError)(Data_Functor.map(((((dictMonadError.MonadThrow0()).Monad0()).Bind1()).Apply0()).Functor0())(Data_Either.Right.create)(a))((function () {
              var $17 = Control_Applicative.pure(((dictMonadError.MonadThrow0()).Monad0()).Applicative0());
              return function ($18) {
                  return $17(Data_Either.Left.create($18));
              };
          })());
      };
  };
  exports["catchError"] = catchError;
  exports["throwError"] = throwError;
  exports["MonadThrow"] = MonadThrow;
  exports["MonadError"] = MonadError;
  exports["try"] = $$try;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad"] = $PS["Control.Monad"] || {};
  var exports = $PS["Control.Monad"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];                
  var Monad = function (Applicative0, Bind1) {
      this.Applicative0 = Applicative0;
      this.Bind1 = Bind1;
  };
  var ap = function (dictMonad) {
      return function (f) {
          return function (a) {
              return Control_Bind.bind(dictMonad.Bind1())(f)(function (f$prime) {
                  return Control_Bind.bind(dictMonad.Bind1())(a)(function (a$prime) {
                      return Control_Applicative.pure(dictMonad.Applicative0())(f$prime(a$prime));
                  });
              });
          };
      };
  };
  exports["Monad"] = Monad;
  exports["ap"] = ap;
})(PS);
(function(exports) {
  "use strict";

  var refEq = function (r1) {
    return function (r2) {
      return r1 === r2;
    };
  };

  exports.eqBooleanImpl = refEq;
  exports.eqIntImpl = refEq;   
  exports.eqCharImpl = refEq;
  exports.eqStringImpl = refEq;
})(PS["Data.Eq"] = PS["Data.Eq"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Eq"] = $PS["Data.Eq"] || {};
  var exports = $PS["Data.Eq"];
  var $foreign = $PS["Data.Eq"];
  var Eq = function (eq) {
      this.eq = eq;
  }; 
  var eqString = new Eq($foreign.eqStringImpl);
  var eqInt = new Eq($foreign.eqIntImpl);
  var eqChar = new Eq($foreign.eqCharImpl);
  var eqBoolean = new Eq($foreign.eqBooleanImpl);
  var eq = function (dict) {
      return dict.eq;
  };
  var notEq = function (dictEq) {
      return function (x) {
          return function (y) {
              return eq(eqBoolean)(eq(dictEq)(x)(y))(false);
          };
      };
  };
  exports["Eq"] = Eq;
  exports["eq"] = eq;
  exports["notEq"] = notEq;
  exports["eqInt"] = eqInt;
  exports["eqChar"] = eqChar;
  exports["eqString"] = eqString;
})(PS);
(function(exports) {
  "use strict";

  var unsafeCompareImpl = function (lt) {
    return function (eq) {
      return function (gt) {
        return function (x) {
          return function (y) {
            return x < y ? lt : x === y ? eq : gt;
          };
        };
      };
    };
  };                                         
  exports.ordIntImpl = unsafeCompareImpl;   
  exports.ordStringImpl = unsafeCompareImpl;
  exports.ordCharImpl = unsafeCompareImpl;
})(PS["Data.Ord"] = PS["Data.Ord"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Ordering"] = $PS["Data.Ordering"] || {};
  var exports = $PS["Data.Ordering"];
  var Data_Eq = $PS["Data.Eq"];                    
  var LT = (function () {
      function LT() {

      };
      LT.value = new LT();
      return LT;
  })();
  var GT = (function () {
      function GT() {

      };
      GT.value = new GT();
      return GT;
  })();
  var EQ = (function () {
      function EQ() {

      };
      EQ.value = new EQ();
      return EQ;
  })();
  var eqOrdering = new Data_Eq.Eq(function (v) {
      return function (v1) {
          if (v instanceof LT && v1 instanceof LT) {
              return true;
          };
          if (v instanceof GT && v1 instanceof GT) {
              return true;
          };
          if (v instanceof EQ && v1 instanceof EQ) {
              return true;
          };
          return false;
      };
  });
  exports["LT"] = LT;
  exports["GT"] = GT;
  exports["EQ"] = EQ;
  exports["eqOrdering"] = eqOrdering;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Ord"] = $PS["Data.Ord"] || {};
  var exports = $PS["Data.Ord"];
  var $foreign = $PS["Data.Ord"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Ordering = $PS["Data.Ordering"];
  var Ord = function (Eq0, compare) {
      this.Eq0 = Eq0;
      this.compare = compare;
  }; 
  var ordString = new Ord(function () {
      return Data_Eq.eqString;
  }, $foreign.ordStringImpl(Data_Ordering.LT.value)(Data_Ordering.EQ.value)(Data_Ordering.GT.value));
  var ordInt = new Ord(function () {
      return Data_Eq.eqInt;
  }, $foreign.ordIntImpl(Data_Ordering.LT.value)(Data_Ordering.EQ.value)(Data_Ordering.GT.value));
  var ordChar = new Ord(function () {
      return Data_Eq.eqChar;
  }, $foreign.ordCharImpl(Data_Ordering.LT.value)(Data_Ordering.EQ.value)(Data_Ordering.GT.value));
  var compare = function (dict) {
      return dict.compare;
  };
  var comparing = function (dictOrd) {
      return function (f) {
          return function (x) {
              return function (y) {
                  return compare(dictOrd)(f(x))(f(y));
              };
          };
      };
  };
  var lessThanOrEq = function (dictOrd) {
      return function (a1) {
          return function (a2) {
              var v = compare(dictOrd)(a1)(a2);
              if (v instanceof Data_Ordering.GT) {
                  return false;
              };
              return true;
          };
      };
  };
  exports["Ord"] = Ord;
  exports["compare"] = compare;
  exports["lessThanOrEq"] = lessThanOrEq;
  exports["comparing"] = comparing;
  exports["ordInt"] = ordInt;
  exports["ordString"] = ordString;
  exports["ordChar"] = ordChar;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Tuple"] = $PS["Data.Tuple"] || {};
  var exports = $PS["Data.Tuple"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Ordering = $PS["Data.Ordering"];                
  var Tuple = (function () {
      function Tuple(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Tuple.create = function (value0) {
          return function (value1) {
              return new Tuple(value0, value1);
          };
      };
      return Tuple;
  })();
  var uncurry = function (f) {
      return function (v) {
          return f(v.value0)(v.value1);
      };
  };
  var snd = function (v) {
      return v.value1;
  };
  var functorTuple = new Data_Functor.Functor(function (f) {
      return function (m) {
          return new Tuple(m.value0, f(m.value1));
      };
  });                                                                                                   
  var fst = function (v) {
      return v.value0;
  }; 
  var eqTuple = function (dictEq) {
      return function (dictEq1) {
          return new Data_Eq.Eq(function (x) {
              return function (y) {
                  return Data_Eq.eq(dictEq)(x.value0)(y.value0) && Data_Eq.eq(dictEq1)(x.value1)(y.value1);
              };
          });
      };
  };
  var ordTuple = function (dictOrd) {
      return function (dictOrd1) {
          return new Data_Ord.Ord(function () {
              return eqTuple(dictOrd.Eq0())(dictOrd1.Eq0());
          }, function (x) {
              return function (y) {
                  var v = Data_Ord.compare(dictOrd)(x.value0)(y.value0);
                  if (v instanceof Data_Ordering.LT) {
                      return Data_Ordering.LT.value;
                  };
                  if (v instanceof Data_Ordering.GT) {
                      return Data_Ordering.GT.value;
                  };
                  return Data_Ord.compare(dictOrd1)(x.value1)(y.value1);
              };
          });
      };
  };
  var bifunctorTuple = new Data_Bifunctor.Bifunctor(function (f) {
      return function (g) {
          return function (v) {
              return new Tuple(f(v.value0), g(v.value1));
          };
      };
  });
  exports["Tuple"] = Tuple;
  exports["fst"] = fst;
  exports["snd"] = snd;
  exports["uncurry"] = uncurry;
  exports["ordTuple"] = ordTuple;
  exports["functorTuple"] = functorTuple;
  exports["bifunctorTuple"] = bifunctorTuple;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.State.Class"] = $PS["Control.Monad.State.Class"] || {};
  var exports = $PS["Control.Monad.State.Class"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unit = $PS["Data.Unit"];                
  var MonadState = function (Monad0, state) {
      this.Monad0 = Monad0;
      this.state = state;
  };
  var state = function (dict) {
      return dict.state;
  };
  var put = function (dictMonadState) {
      return function (s) {
          return state(dictMonadState)(function (v) {
              return new Data_Tuple.Tuple(Data_Unit.unit, s);
          });
      };
  };
  var modify_ = function (dictMonadState) {
      return function (f) {
          return state(dictMonadState)(function (s) {
              return new Data_Tuple.Tuple(Data_Unit.unit, f(s));
          });
      };
  };
  var gets = function (dictMonadState) {
      return function (f) {
          return state(dictMonadState)(function (s) {
              return new Data_Tuple.Tuple(f(s), s);
          });
      };
  };
  var get = function (dictMonadState) {
      return state(dictMonadState)(function (s) {
          return new Data_Tuple.Tuple(s, s);
      });
  };
  exports["state"] = state;
  exports["MonadState"] = MonadState;
  exports["get"] = get;
  exports["gets"] = gets;
  exports["put"] = put;
  exports["modify_"] = modify_;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Trans.Class"] = $PS["Control.Monad.Trans.Class"] || {};
  var exports = $PS["Control.Monad.Trans.Class"];
  var MonadTrans = function (lift) {
      this.lift = lift;
  };
  var lift = function (dict) {
      return dict.lift;
  };
  exports["lift"] = lift;
  exports["MonadTrans"] = MonadTrans;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Class"] = $PS["Effect.Class"] || {};
  var exports = $PS["Effect.Class"];         
  var MonadEffect = function (Monad0, liftEffect) {
      this.Monad0 = Monad0;
      this.liftEffect = liftEffect;
  };                                                         
  var liftEffect = function (dict) {
      return dict.liftEffect;
  };
  exports["liftEffect"] = liftEffect;
  exports["MonadEffect"] = MonadEffect;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Except.Trans"] = $PS["Control.Monad.Except.Trans"] || {};
  var exports = $PS["Control.Monad.Except.Trans"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Control_Monad_Trans_Class = $PS["Control.Monad.Trans.Class"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Effect_Class = $PS["Effect.Class"];                
  var ExceptT = function (x) {
      return x;
  };
  var runExceptT = function (v) {
      return v;
  };          
  var monadTransExceptT = new Control_Monad_Trans_Class.MonadTrans(function (dictMonad) {
      return function (m) {
          return Control_Bind.bind(dictMonad.Bind1())(m)(function (a) {
              return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Either.Right(a));
          });
      };
  });
  var mapExceptT = function (f) {
      return function (v) {
          return f(v);
      };
  };
  var functorExceptT = function (dictFunctor) {
      return new Data_Functor.Functor(function (f) {
          return mapExceptT(Data_Functor.map(dictFunctor)(Data_Functor.map(Data_Either.functorEither)(f)));
      });
  };
  var monadExceptT = function (dictMonad) {
      return new Control_Monad.Monad(function () {
          return applicativeExceptT(dictMonad);
      }, function () {
          return bindExceptT(dictMonad);
      });
  };
  var bindExceptT = function (dictMonad) {
      return new Control_Bind.Bind(function () {
          return applyExceptT(dictMonad);
      }, function (v) {
          return function (k) {
              return Control_Bind.bind(dictMonad.Bind1())(v)(Data_Either.either((function () {
                  var $90 = Control_Applicative.pure(dictMonad.Applicative0());
                  return function ($91) {
                      return $90(Data_Either.Left.create($91));
                  };
              })())(function (a) {
                  var v1 = k(a);
                  return v1;
              }));
          };
      });
  };
  var applyExceptT = function (dictMonad) {
      return new Control_Apply.Apply(function () {
          return functorExceptT(((dictMonad.Bind1()).Apply0()).Functor0());
      }, Control_Monad.ap(monadExceptT(dictMonad)));
  };
  var applicativeExceptT = function (dictMonad) {
      return new Control_Applicative.Applicative(function () {
          return applyExceptT(dictMonad);
      }, (function () {
          var $92 = Control_Applicative.pure(dictMonad.Applicative0());
          return function ($93) {
              return ExceptT($92(Data_Either.Right.create($93)));
          };
      })());
  };
  var monadEffectExceptT = function (dictMonadEffect) {
      return new Effect_Class.MonadEffect(function () {
          return monadExceptT(dictMonadEffect.Monad0());
      }, (function () {
          var $94 = Control_Monad_Trans_Class.lift(monadTransExceptT)(dictMonadEffect.Monad0());
          var $95 = Effect_Class.liftEffect(dictMonadEffect);
          return function ($96) {
              return $94($95($96));
          };
      })());
  };
  var monadStateExceptT = function (dictMonadState) {
      return new Control_Monad_State_Class.MonadState(function () {
          return monadExceptT(dictMonadState.Monad0());
      }, function (f) {
          return Control_Monad_Trans_Class.lift(monadTransExceptT)(dictMonadState.Monad0())(Control_Monad_State_Class.state(dictMonadState)(f));
      });
  };
  var monadThrowExceptT = function (dictMonad) {
      return new Control_Monad_Error_Class.MonadThrow(function () {
          return monadExceptT(dictMonad);
      }, (function () {
          var $102 = Control_Applicative.pure(dictMonad.Applicative0());
          return function ($103) {
              return ExceptT($102(Data_Either.Left.create($103)));
          };
      })());
  };
  var monadErrorExceptT = function (dictMonad) {
      return new Control_Monad_Error_Class.MonadError(function () {
          return monadThrowExceptT(dictMonad);
      }, function (v) {
          return function (k) {
              return Control_Bind.bind(dictMonad.Bind1())(v)(Data_Either.either(function (a) {
                  var v1 = k(a);
                  return v1;
              })((function () {
                  var $104 = Control_Applicative.pure(dictMonad.Applicative0());
                  return function ($105) {
                      return $104(Data_Either.Right.create($105));
                  };
              })()));
          };
      });
  };
  exports["ExceptT"] = ExceptT;
  exports["runExceptT"] = runExceptT;
  exports["mapExceptT"] = mapExceptT;
  exports["functorExceptT"] = functorExceptT;
  exports["applyExceptT"] = applyExceptT;
  exports["applicativeExceptT"] = applicativeExceptT;
  exports["bindExceptT"] = bindExceptT;
  exports["monadTransExceptT"] = monadTransExceptT;
  exports["monadEffectExceptT"] = monadEffectExceptT;
  exports["monadThrowExceptT"] = monadThrowExceptT;
  exports["monadErrorExceptT"] = monadErrorExceptT;
  exports["monadStateExceptT"] = monadStateExceptT;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Identity"] = $PS["Data.Identity"] || {};
  var exports = $PS["Data.Identity"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Newtype = $PS["Data.Newtype"];          
  var Identity = function (x) {
      return x;
  };
  var newtypeIdentity = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Identity);
  var functorIdentity = new Data_Functor.Functor(function (f) {
      return function (m) {
          return f(m);
      };
  });
  var applyIdentity = new Control_Apply.Apply(function () {
      return functorIdentity;
  }, function (v) {
      return function (v1) {
          return v(v1);
      };
  });
  var bindIdentity = new Control_Bind.Bind(function () {
      return applyIdentity;
  }, function (v) {
      return function (f) {
          return f(v);
      };
  });
  var applicativeIdentity = new Control_Applicative.Applicative(function () {
      return applyIdentity;
  }, Identity);
  var monadIdentity = new Control_Monad.Monad(function () {
      return applicativeIdentity;
  }, function () {
      return bindIdentity;
  });
  exports["Identity"] = Identity;
  exports["newtypeIdentity"] = newtypeIdentity;
  exports["functorIdentity"] = functorIdentity;
  exports["monadIdentity"] = monadIdentity;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Except"] = $PS["Control.Monad.Except"] || {};
  var exports = $PS["Control.Monad.Except"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Newtype = $PS["Data.Newtype"];                                                
  var runExcept = (function () {
      var $0 = Data_Newtype.unwrap(Data_Identity.newtypeIdentity);
      return function ($1) {
          return $0(Control_Monad_Except_Trans.runExceptT($1));
      };
  })();
  var mapExcept = function (f) {
      return Control_Monad_Except_Trans.mapExceptT((function () {
          var $2 = Data_Newtype.unwrap(Data_Identity.newtypeIdentity);
          return function ($3) {
              return Data_Identity.Identity(f($2($3)));
          };
      })());
  };
  exports["runExcept"] = runExcept;
  exports["mapExcept"] = mapExcept;
})(PS);
(function(exports) {
  "use strict";

  function id(x) {
    return x;
  }                      
  exports.fromObject = id;

  exports.stringify = function (j) {
    return JSON.stringify(j);
  };

  function isArray(a) {
    return Object.prototype.toString.call(a) === "[object Array]";
  }

  exports._caseJson = function (isNull, isBool, isNum, isStr, isArr, isObj, j) {
    if (j == null) return isNull();
    else if (typeof j === "boolean") return isBool(j);
    else if (typeof j === "number") return isNum(j);
    else if (typeof j === "string") return isStr(j);
    else if (Object.prototype.toString.call(j) === "[object Array]")
      return isArr(j);
    else return isObj(j);
  };
})(PS["Data.Argonaut.Core"] = PS["Data.Argonaut.Core"] || {});
(function(exports) {
  "use strict";

  exports.empty = {};

  exports.runST = function (f) {
    return f();
  };

  exports._foldM = function (bind) {
    return function (f) {
      return function (mz) {
        return function (m) {
          var acc = mz;
          function g(k) {
            return function (z) {
              return f(z)(k)(m[k]);
            };
          }
          for (var k in m) {
            if (hasOwnProperty.call(m, k)) {
              acc = bind(acc)(g(k));
            }
          }
          return acc;
        };
      };
    };
  };

  exports._lookup = function (no, yes, k, m) {
    return k in m ? yes(m[k]) : no;
  };

  function toArrayWithKey(f) {
    return function (m) {
      var r = [];
      for (var k in m) {
        if (hasOwnProperty.call(m, k)) {
          r.push(f(k)(m[k]));
        }
      }
      return r;
    };
  }
})(PS["Foreign.Object"] = PS["Foreign.Object"] || {});
(function(exports) {
  "use strict";

  exports.map_ = function (f) {
    return function (a) {
      return function () {
        return f(a());
      };
    };
  };

  exports.foreach = function (as) {
    return function (f) {
      return function () {
        for (var i = 0, l = as.length; i < l; i++) {
          f(as[i])();
        }
      };
    };
  };
})(PS["Control.Monad.ST.Internal"] = PS["Control.Monad.ST.Internal"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.ST.Internal"] = $PS["Control.Monad.ST.Internal"] || {};
  var exports = $PS["Control.Monad.ST.Internal"];
  var $foreign = $PS["Control.Monad.ST.Internal"];
  var Data_Functor = $PS["Data.Functor"];
  var functorST = new Data_Functor.Functor($foreign.map_);
  exports["functorST"] = functorST;
  exports["foreach"] = $foreign.foreach;
})(PS);
(function(exports) {
  "use strict";

  //------------------------------------------------------------------------------
  // Array creation --------------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.range = function (start) {
    return function (end) {
      var step = start > end ? -1 : 1;
      var result = new Array(step * (end - start) + 1);
      var i = start, n = 0;
      while (i !== end) {
        result[n++] = i;
        i += step;
      }
      result[n] = i;
      return result;
    };
  };                                                                                                 

  exports.fromFoldableImpl = (function () {
    function Cons(head, tail) {
      this.head = head;
      this.tail = tail;
    }
    var emptyList = {};

    function curryCons(head) {
      return function (tail) {
        return new Cons(head, tail);
      };
    }

    function listToArray(list) {
      var result = [];
      var count = 0;
      var xs = list;
      while (xs !== emptyList) {
        result[count++] = xs.head;
        xs = xs.tail;
      }
      return result;
    }

    return function (foldr) {
      return function (xs) {
        return listToArray(foldr(curryCons)(emptyList)(xs));
      };
    };
  })();

  //------------------------------------------------------------------------------
  // Array size ------------------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.length = function (xs) {
    return xs.length;
  };

  //------------------------------------------------------------------------------
  // Extending arrays ------------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.cons = function (e) {
    return function (l) {
      return [e].concat(l);
    };
  };

  exports.snoc = function (l) {
    return function (e) {
      var l1 = l.slice();
      l1.push(e);
      return l1;
    };
  };

  //------------------------------------------------------------------------------
  // Non-indexed reads -----------------------------------------------------------
  //------------------------------------------------------------------------------

  exports["uncons'"] = function (empty) {
    return function (next) {
      return function (xs) {
        return xs.length === 0 ? empty({}) : next(xs[0])(xs.slice(1));
      };
    };
  };

  //------------------------------------------------------------------------------
  // Indexed operations ----------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.indexImpl = function (just) {
    return function (nothing) {
      return function (xs) {
        return function (i) {
          return i < 0 || i >= xs.length ? nothing :  just(xs[i]);
        };
      };
    };
  };

  exports.filter = function (f) {
    return function (xs) {
      return xs.filter(f);
    };
  };

  //------------------------------------------------------------------------------
  // Sorting ---------------------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.sortImpl = function (f) {
    return function (l) {
      return l.slice().sort(function (x, y) {
        return f(x)(y);
      });
    };
  };

  //------------------------------------------------------------------------------
  // Subarrays -------------------------------------------------------------------
  //------------------------------------------------------------------------------

  exports.slice = function (s) {
    return function (e) {
      return function (l) {
        return l.slice(s, e);
      };
    };
  };
})(PS["Data.Array"] = PS["Data.Array"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Alt"] = $PS["Control.Alt"] || {};
  var exports = $PS["Control.Alt"];                          
  var Alt = function (Functor0, alt) {
      this.Functor0 = Functor0;
      this.alt = alt;
  };                                                       
  var alt = function (dict) {
      return dict.alt;
  };
  exports["Alt"] = Alt;
  exports["alt"] = alt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Lazy"] = $PS["Control.Lazy"] || {};
  var exports = $PS["Control.Lazy"];               
  var Lazy = function (defer) {
      this.defer = defer;
  }; 
  var defer = function (dict) {
      return dict.defer;
  };
  exports["defer"] = defer;
  exports["Lazy"] = Lazy;
})(PS);
(function(exports) {
  "use strict";

  exports.foldrArray = function (f) {
    return function (init) {
      return function (xs) {
        var acc = init;
        var len = xs.length;
        for (var i = len - 1; i >= 0; i--) {
          acc = f(xs[i])(acc);
        }
        return acc;
      };
    };
  };

  exports.foldlArray = function (f) {
    return function (init) {
      return function (xs) {
        var acc = init;
        var len = xs.length;
        for (var i = 0; i < len; i++) {
          acc = f(acc)(xs[i]);
        }
        return acc;
      };
    };
  };
})(PS["Data.Foldable"] = PS["Data.Foldable"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Foldable"] = $PS["Data.Foldable"] || {};
  var exports = $PS["Data.Foldable"];
  var $foreign = $PS["Data.Foldable"];
  var Control_Category = $PS["Control.Category"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_HeytingAlgebra = $PS["Data.HeytingAlgebra"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Monoid_Disj = $PS["Data.Monoid.Disj"];
  var Data_Monoid_Endo = $PS["Data.Monoid.Endo"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Ordering = $PS["Data.Ordering"];
  var Data_Semigroup = $PS["Data.Semigroup"];      
  var Foldable = function (foldMap, foldl, foldr) {
      this.foldMap = foldMap;
      this.foldl = foldl;
      this.foldr = foldr;
  };
  var foldr = function (dict) {
      return dict.foldr;
  };
  var foldl = function (dict) {
      return dict.foldl;
  };
  var intercalate = function (dictFoldable) {
      return function (dictMonoid) {
          return function (sep) {
              return function (xs) {
                  var go = function (v) {
                      return function (x) {
                          if (v.init) {
                              return {
                                  init: false,
                                  acc: x
                              };
                          };
                          return {
                              init: false,
                              acc: Data_Semigroup.append(dictMonoid.Semigroup0())(v.acc)(Data_Semigroup.append(dictMonoid.Semigroup0())(sep)(x))
                          };
                      };
                  };
                  return (foldl(dictFoldable)(go)({
                      init: true,
                      acc: Data_Monoid.mempty(dictMonoid)
                  })(xs)).acc;
              };
          };
      };
  };
  var maximumBy = function (dictFoldable) {
      return function (cmp) {
          var max$prime = function (v) {
              return function (v1) {
                  if (v instanceof Data_Maybe.Nothing) {
                      return new Data_Maybe.Just(v1);
                  };
                  if (v instanceof Data_Maybe.Just) {
                      return new Data_Maybe.Just((function () {
                          var $116 = Data_Eq.eq(Data_Ordering.eqOrdering)(cmp(v.value0)(v1))(Data_Ordering.GT.value);
                          if ($116) {
                              return v.value0;
                          };
                          return v1;
                      })());
                  };
                  throw new Error("Failed pattern match at Data.Foldable (line 389, column 3 - line 389, column 27): " + [ v.constructor.name, v1.constructor.name ]);
              };
          };
          return foldl(dictFoldable)(max$prime)(Data_Maybe.Nothing.value);
      };
  };
  var maximum = function (dictOrd) {
      return function (dictFoldable) {
          return maximumBy(dictFoldable)(Data_Ord.compare(dictOrd));
      };
  }; 
  var foldMapDefaultR = function (dictFoldable) {
      return function (dictMonoid) {
          return function (f) {
              return foldr(dictFoldable)(function (x) {
                  return function (acc) {
                      return Data_Semigroup.append(dictMonoid.Semigroup0())(f(x))(acc);
                  };
              })(Data_Monoid.mempty(dictMonoid));
          };
      };
  };
  var foldableArray = new Foldable(function (dictMonoid) {
      return foldMapDefaultR(foldableArray)(dictMonoid);
  }, $foreign.foldlArray, $foreign.foldrArray);
  var foldMapDefaultL = function (dictFoldable) {
      return function (dictMonoid) {
          return function (f) {
              return foldl(dictFoldable)(function (acc) {
                  return function (x) {
                      return Data_Semigroup.append(dictMonoid.Semigroup0())(acc)(f(x));
                  };
              })(Data_Monoid.mempty(dictMonoid));
          };
      };
  };
  var foldMap = function (dict) {
      return dict.foldMap;
  };
  var foldrDefault = function (dictFoldable) {
      return function (c) {
          return function (u) {
              return function (xs) {
                  return Data_Newtype.unwrap(Data_Newtype.newtypeEndo)(foldMap(dictFoldable)(Data_Monoid_Endo.monoidEndo(Control_Category.categoryFn))(function ($203) {
                      return Data_Monoid_Endo.Endo(c($203));
                  })(xs))(u);
              };
          };
      };
  };
  var fold = function (dictFoldable) {
      return function (dictMonoid) {
          return foldMap(dictFoldable)(dictMonoid)(Control_Category.identity(Control_Category.categoryFn));
      };
  };
  var any = function (dictFoldable) {
      return function (dictHeytingAlgebra) {
          return Data_Newtype.alaF(Data_Functor.functorFn)(Data_Functor.functorFn)(Data_Newtype.newtypeDisj)(Data_Newtype.newtypeDisj)(Data_Monoid_Disj.Disj)(foldMap(dictFoldable)(Data_Monoid_Disj.monoidDisj(dictHeytingAlgebra)));
      };
  };
  var elem = function (dictFoldable) {
      return function (dictEq) {
          var $204 = any(dictFoldable)(Data_HeytingAlgebra.heytingAlgebraBoolean);
          var $205 = Data_Eq.eq(dictEq);
          return function ($206) {
              return $204($205($206));
          };
      };
  };
  exports["Foldable"] = Foldable;
  exports["foldr"] = foldr;
  exports["foldl"] = foldl;
  exports["foldMap"] = foldMap;
  exports["foldrDefault"] = foldrDefault;
  exports["foldMapDefaultL"] = foldMapDefaultL;
  exports["fold"] = fold;
  exports["intercalate"] = intercalate;
  exports["any"] = any;
  exports["elem"] = elem;
  exports["maximum"] = maximum;
  exports["foldableArray"] = foldableArray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Array"] = $PS["Data.Array"] || {};
  var exports = $PS["Data.Array"];
  var $foreign = $PS["Data.Array"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Lazy = $PS["Control.Lazy"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Ordering = $PS["Data.Ordering"];
  var tail = $foreign["uncons'"](Data_Function["const"](Data_Maybe.Nothing.value))(function (v) {
      return function (xs) {
          return new Data_Maybe.Just(xs);
      };
  });
  var sortBy = function (comp) {
      return function (xs) {
          var comp$prime = function (x) {
              return function (y) {
                  var v = comp(x)(y);
                  if (v instanceof Data_Ordering.GT) {
                      return 1;
                  };
                  if (v instanceof Data_Ordering.EQ) {
                      return 0;
                  };
                  if (v instanceof Data_Ordering.LT) {
                      return -1 | 0;
                  };
                  throw new Error("Failed pattern match at Data.Array (line 702, column 15 - line 705, column 13): " + [ v.constructor.name ]);
              };
          };
          return $foreign.sortImpl(comp$prime)(xs);
      };
  };
  var sortWith = function (dictOrd) {
      return function (f) {
          return sortBy(Data_Ord.comparing(dictOrd)(f));
      };
  };
  var some = function (dictAlternative) {
      return function (dictLazy) {
          return function (v) {
              return Control_Apply.apply((dictAlternative.Applicative0()).Apply0())(Data_Functor.map(((dictAlternative.Plus1()).Alt0()).Functor0())($foreign.cons)(v))(Control_Lazy.defer(dictLazy)(function (v1) {
                  return many(dictAlternative)(dictLazy)(v);
              }));
          };
      };
  };
  var many = function (dictAlternative) {
      return function (dictLazy) {
          return function (v) {
              return Control_Alt.alt((dictAlternative.Plus1()).Alt0())(some(dictAlternative)(dictLazy)(v))(Control_Applicative.pure(dictAlternative.Applicative0())([  ]));
          };
      };
  };
  var index = $foreign.indexImpl(Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  var span = function (p) {
      return function (arr) {
          var go = function ($copy_i) {
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(i) {
                  var v = index(arr)(i);
                  if (v instanceof Data_Maybe.Just) {
                      var $60 = p(v.value0);
                      if ($60) {
                          $copy_i = i + 1 | 0;
                          return;
                      };
                      $tco_done = true;
                      return new Data_Maybe.Just(i);
                  };
                  if (v instanceof Data_Maybe.Nothing) {
                      $tco_done = true;
                      return Data_Maybe.Nothing.value;
                  };
                  throw new Error("Failed pattern match at Data.Array (line 834, column 5 - line 836, column 25): " + [ v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($copy_i);
              };
              return $tco_result;
          };
          var breakIndex = go(0);
          if (breakIndex instanceof Data_Maybe.Just && breakIndex.value0 === 0) {
              return {
                  init: [  ],
                  rest: arr
              };
          };
          if (breakIndex instanceof Data_Maybe.Just) {
              return {
                  init: $foreign.slice(0)(breakIndex.value0)(arr),
                  rest: $foreign.slice(breakIndex.value0)($foreign.length(arr))(arr)
              };
          };
          if (breakIndex instanceof Data_Maybe.Nothing) {
              return {
                  init: arr,
                  rest: [  ]
              };
          };
          throw new Error("Failed pattern match at Data.Array (line 821, column 3 - line 827, column 30): " + [ breakIndex.constructor.name ]);
      };
  };
  var head = function (xs) {
      return index(xs)(0);
  };
  var fromFoldable = function (dictFoldable) {
      return $foreign.fromFoldableImpl(Data_Foldable.foldr(dictFoldable));
  };
  var dropWhile = function (p) {
      return function (xs) {
          return (span(p)(xs)).rest;
      };
  };
  exports["fromFoldable"] = fromFoldable;
  exports["some"] = some;
  exports["many"] = many;
  exports["head"] = head;
  exports["tail"] = tail;
  exports["index"] = index;
  exports["sortWith"] = sortWith;
  exports["dropWhile"] = dropWhile;
  exports["range"] = $foreign.range;
  exports["length"] = $foreign.length;
  exports["snoc"] = $foreign.snoc;
  exports["filter"] = $foreign.filter;
})(PS);
(function(exports) {
  "use strict";

  exports.runFn4 = function (fn) {
    return function (a) {
      return function (b) {
        return function (c) {
          return function (d) {
            return fn(a, b, c, d);
          };
        };
      };
    };
  };
})(PS["Data.Function.Uncurried"] = PS["Data.Function.Uncurried"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Function.Uncurried"] = $PS["Data.Function.Uncurried"] || {};
  var exports = $PS["Data.Function.Uncurried"];
  var $foreign = $PS["Data.Function.Uncurried"];
  exports["runFn4"] = $foreign.runFn4;
})(PS);
(function(exports) {
  "use strict";

  exports["new"] = function () {
    return {};
  };

  exports.poke = function (k) {
    return function (v) {
      return function (m) {
        return function () {
          m[k] = v;
          return m;
        };
      };
    };
  };
})(PS["Foreign.Object.ST"] = PS["Foreign.Object.ST"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Foreign.Object.ST"] = $PS["Foreign.Object.ST"] || {};
  var exports = $PS["Foreign.Object.ST"];
  var $foreign = $PS["Foreign.Object.ST"];
  exports["new"] = $foreign["new"];
  exports["poke"] = $foreign.poke;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Foreign.Object"] = $PS["Foreign.Object"] || {};
  var exports = $PS["Foreign.Object"];
  var $foreign = $PS["Foreign.Object"];
  var Control_Monad_ST_Internal = $PS["Control.Monad.ST.Internal"];
  var Data_Array = $PS["Data.Array"];
  var Data_Function = $PS["Data.Function"];
  var Data_Function_Uncurried = $PS["Data.Function.Uncurried"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Foreign_Object_ST = $PS["Foreign.Object.ST"];
  var lookup = Data_Function_Uncurried.runFn4($foreign["_lookup"])(Data_Maybe.Nothing.value)(Data_Maybe.Just.create);
  var fromFoldable = function (dictFoldable) {
      return function (l) {
          return $foreign.runST(function __do() {
              var s = Foreign_Object_ST["new"]();
              Control_Monad_ST_Internal.foreach(Data_Array.fromFoldable(dictFoldable)(l))(function (v) {
                  return Data_Functor["void"](Control_Monad_ST_Internal.functorST)(Foreign_Object_ST.poke(v.value0)(v.value1)(s));
              })();
              return s;
          });
      };
  };
  var fold = $foreign["_foldM"](Data_Function.applyFlipped);
  exports["lookup"] = lookup;
  exports["fromFoldable"] = fromFoldable;
  exports["fold"] = fold;
  exports["empty"] = $foreign.empty;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Argonaut.Core"] = $PS["Data.Argonaut.Core"] || {};
  var exports = $PS["Data.Argonaut.Core"];
  var $foreign = $PS["Data.Argonaut.Core"];
  var Data_Function = $PS["Data.Function"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Foreign_Object = $PS["Foreign.Object"];                
  var verbJsonType = function (def) {
      return function (f) {
          return function (g) {
              return g(def)(f);
          };
      };
  };
  var toJsonType = verbJsonType(Data_Maybe.Nothing.value)(Data_Maybe.Just.create);
  var jsonEmptyObject = $foreign.fromObject(Foreign_Object.empty);
  var caseJsonString = function (d) {
      return function (f) {
          return function (j) {
              return $foreign["_caseJson"](Data_Function["const"](d), Data_Function["const"](d), Data_Function["const"](d), f, Data_Function["const"](d), Data_Function["const"](d), j);
          };
      };
  };                                        
  var caseJsonObject = function (d) {
      return function (f) {
          return function (j) {
              return $foreign["_caseJson"](Data_Function["const"](d), Data_Function["const"](d), Data_Function["const"](d), Data_Function["const"](d), Data_Function["const"](d), f, j);
          };
      };
  };                                        
  var toObject = toJsonType(caseJsonObject);
  exports["caseJsonString"] = caseJsonString;
  exports["toObject"] = toObject;
  exports["jsonEmptyObject"] = jsonEmptyObject;
  exports["stringify"] = $foreign.stringify;
})(PS);
(function(exports) {
  "use strict";

  exports._jsonParser = function (fail, succ, s) {
    try {
      return succ(JSON.parse(s));
    }
    catch (e) {
      return fail(e.message);
    }
  };
})(PS["Data.Argonaut.Parser"] = PS["Data.Argonaut.Parser"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Argonaut.Parser"] = $PS["Data.Argonaut.Parser"] || {};
  var exports = $PS["Data.Argonaut.Parser"];
  var $foreign = $PS["Data.Argonaut.Parser"];
  var Data_Either = $PS["Data.Either"];                
  var jsonParser = function (j) {
      return $foreign["_jsonParser"](Data_Either.Left.create, Data_Either.Right.create, j);
  };
  exports["jsonParser"] = jsonParser;
})(PS);
(function(exports) {
  "use strict";

  exports.replace = function (s1) {
    return function (s2) {
      return function (s3) {
        return s3.replace(s1, s2);
      };
    };
  };

  exports.replaceAll = function (s1) {
    return function (s2) {
      return function (s3) {
        return s3.replace(new RegExp(s1.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&"), "g"), s2); // eslint-disable-line no-useless-escape
      };
    };
  };

  exports.split = function (sep) {
    return function (s) {
      return s.split(sep);
    };
  };

  exports.toLower = function (s) {
    return s.toLowerCase();
  };

  exports.joinWith = function (s) {
    return function (xs) {
      return xs.join(s);
    };
  };
})(PS["Data.String.Common"] = PS["Data.String.Common"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.Common"] = $PS["Data.String.Common"] || {};
  var exports = $PS["Data.String.Common"];
  var $foreign = $PS["Data.String.Common"];                
  var $$null = function (s) {
      return s === "";
  };
  exports["null"] = $$null;
  exports["replace"] = $foreign.replace;
  exports["replaceAll"] = $foreign.replaceAll;
  exports["split"] = $foreign.split;
  exports["toLower"] = $foreign.toLower;
  exports["joinWith"] = $foreign.joinWith;
})(PS);
(function(exports) {
  "use strict";

  // jshint maxparams: 3

  exports.traverseArrayImpl = function () {
    function array1(a) {
      return [a];
    }

    function array2(a) {
      return function (b) {
        return [a, b];
      };
    }

    function array3(a) {
      return function (b) {
        return function (c) {
          return [a, b, c];
        };
      };
    }

    function concat2(xs) {
      return function (ys) {
        return xs.concat(ys);
      };
    }

    return function (apply) {
      return function (map) {
        return function (pure) {
          return function (f) {
            return function (array) {
              function go(bot, top) {
                switch (top - bot) {
                case 0: return pure([]);
                case 1: return map(array1)(f(array[bot]));
                case 2: return apply(map(array2)(f(array[bot])))(f(array[bot + 1]));
                case 3: return apply(apply(map(array3)(f(array[bot])))(f(array[bot + 1])))(f(array[bot + 2]));
                default:
                  // This slightly tricky pivot selection aims to produce two
                  // even-length partitions where possible.
                  var pivot = bot + Math.floor((top - bot) / 4) * 2;
                  return apply(map(concat2)(go(bot, pivot)))(go(pivot, top));
                }
              }
              return go(0, array.length);
            };
          };
        };
      };
    };
  }();
})(PS["Data.Traversable"] = PS["Data.Traversable"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Traversable"] = $PS["Data.Traversable"] || {};
  var exports = $PS["Data.Traversable"];
  var $foreign = $PS["Data.Traversable"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Category = $PS["Control.Category"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];                                                      
  var Traversable = function (Foldable1, Functor0, sequence, traverse) {
      this.Foldable1 = Foldable1;
      this.Functor0 = Functor0;
      this.sequence = sequence;
      this.traverse = traverse;
  };
  var traverse = function (dict) {
      return dict.traverse;
  }; 
  var sequenceDefault = function (dictTraversable) {
      return function (dictApplicative) {
          return traverse(dictTraversable)(dictApplicative)(Control_Category.identity(Control_Category.categoryFn));
      };
  };
  var traversableArray = new Traversable(function () {
      return Data_Foldable.foldableArray;
  }, function () {
      return Data_Functor.functorArray;
  }, function (dictApplicative) {
      return sequenceDefault(traversableArray)(dictApplicative);
  }, function (dictApplicative) {
      return $foreign.traverseArrayImpl(Control_Apply.apply(dictApplicative.Apply0()))(Data_Functor.map((dictApplicative.Apply0()).Functor0()))(Control_Applicative.pure(dictApplicative));
  });
  var $$for = function (dictApplicative) {
      return function (dictTraversable) {
          return function (x) {
              return function (f) {
                  return traverse(dictTraversable)(dictApplicative)(f)(x);
              };
          };
      };
  };
  exports["Traversable"] = Traversable;
  exports["traverse"] = traverse;
  exports["for"] = $$for;
  exports["traversableArray"] = traversableArray;
})(PS);
(function(exports) {
  /* globals exports */
  "use strict";               

  exports.readInt = function (radix) {
    return function (n) {
      return parseInt(n, radix);
    };
  };                                                 

  var encdecURI = function (encdec) {
    return function (fail, succ, s) {
      try {
        return succ(encdec(s));
      }
      catch (e) {
        return fail(e.message);
      }
    };
  };                                        
  exports._decodeURIComponent = encdecURI(decodeURIComponent);
  exports._encodeURIComponent = encdecURI(encodeURIComponent);
})(PS["Global"] = PS["Global"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Global"] = $PS["Global"] || {};
  var exports = $PS["Global"];
  var $foreign = $PS["Global"];
  var Data_Function = $PS["Data.Function"];
  var Data_Maybe = $PS["Data.Maybe"];
  var $$encodeURIComponent = function (s) {
      return $foreign["_encodeURIComponent"](Data_Function["const"](Data_Maybe.Nothing.value), Data_Maybe.Just.create, s);
  };
  var $$decodeURIComponent = function (s) {
      return $foreign["_decodeURIComponent"](Data_Function["const"](Data_Maybe.Nothing.value), Data_Maybe.Just.create, s);
  };
  exports["decodeURIComponent"] = $$decodeURIComponent;
  exports["encodeURIComponent"] = $$encodeURIComponent;
  exports["readInt"] = $foreign.readInt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.FormURLEncoded"] = $PS["Data.FormURLEncoded"] || {};
  var exports = $PS["Data.FormURLEncoded"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_Traversable = $PS["Data.Traversable"];
  var Global = $PS["Global"];                
  var FormURLEncoded = function (x) {
      return x;
  };
  var toArray = function (v) {
      return v;
  };                                                                                                                 
  var encode = (function () {
      var encodePart = function (v) {
          if (v.value1 instanceof Data_Maybe.Nothing) {
              return Global["encodeURIComponent"](v.value0);
          };
          if (v.value1 instanceof Data_Maybe.Just) {
              return Control_Apply.apply(Data_Maybe.applyMaybe)(Data_Functor.map(Data_Maybe.functorMaybe)(function (key) {
                  return function (val) {
                      return key + ("=" + val);
                  };
              })(Global["encodeURIComponent"](v.value0)))(Global["encodeURIComponent"](v.value1.value0));
          };
          throw new Error("Failed pattern match at Data.FormURLEncoded (line 37, column 18 - line 39, column 108): " + [ v.constructor.name ]);
      };
      var $19 = Data_Functor.map(Data_Maybe.functorMaybe)(Data_String_Common.joinWith("&"));
      var $20 = Data_Traversable.traverse(Data_Traversable.traversableArray)(Data_Maybe.applicativeMaybe)(encodePart);
      return function ($21) {
          return $19($20(toArray($21)));
      };
  })();
  exports["FormURLEncoded"] = FormURLEncoded;
  exports["encode"] = encode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.HTTP.Method"] = $PS["Data.HTTP.Method"] || {};
  var exports = $PS["Data.HTTP.Method"];
  var Data_Either = $PS["Data.Either"];
  var Data_Show = $PS["Data.Show"];                                  
  var OPTIONS = (function () {
      function OPTIONS() {

      };
      OPTIONS.value = new OPTIONS();
      return OPTIONS;
  })();
  var GET = (function () {
      function GET() {

      };
      GET.value = new GET();
      return GET;
  })();
  var HEAD = (function () {
      function HEAD() {

      };
      HEAD.value = new HEAD();
      return HEAD;
  })();
  var POST = (function () {
      function POST() {

      };
      POST.value = new POST();
      return POST;
  })();
  var PUT = (function () {
      function PUT() {

      };
      PUT.value = new PUT();
      return PUT;
  })();
  var DELETE = (function () {
      function DELETE() {

      };
      DELETE.value = new DELETE();
      return DELETE;
  })();
  var TRACE = (function () {
      function TRACE() {

      };
      TRACE.value = new TRACE();
      return TRACE;
  })();
  var CONNECT = (function () {
      function CONNECT() {

      };
      CONNECT.value = new CONNECT();
      return CONNECT;
  })();
  var PROPFIND = (function () {
      function PROPFIND() {

      };
      PROPFIND.value = new PROPFIND();
      return PROPFIND;
  })();
  var PROPPATCH = (function () {
      function PROPPATCH() {

      };
      PROPPATCH.value = new PROPPATCH();
      return PROPPATCH;
  })();
  var MKCOL = (function () {
      function MKCOL() {

      };
      MKCOL.value = new MKCOL();
      return MKCOL;
  })();
  var COPY = (function () {
      function COPY() {

      };
      COPY.value = new COPY();
      return COPY;
  })();
  var MOVE = (function () {
      function MOVE() {

      };
      MOVE.value = new MOVE();
      return MOVE;
  })();
  var LOCK = (function () {
      function LOCK() {

      };
      LOCK.value = new LOCK();
      return LOCK;
  })();
  var UNLOCK = (function () {
      function UNLOCK() {

      };
      UNLOCK.value = new UNLOCK();
      return UNLOCK;
  })();
  var PATCH = (function () {
      function PATCH() {

      };
      PATCH.value = new PATCH();
      return PATCH;
  })();
  var unCustomMethod = function (v) {
      return v;
  };
  var showMethod = new Data_Show.Show(function (v) {
      if (v instanceof OPTIONS) {
          return "OPTIONS";
      };
      if (v instanceof GET) {
          return "GET";
      };
      if (v instanceof HEAD) {
          return "HEAD";
      };
      if (v instanceof POST) {
          return "POST";
      };
      if (v instanceof PUT) {
          return "PUT";
      };
      if (v instanceof DELETE) {
          return "DELETE";
      };
      if (v instanceof TRACE) {
          return "TRACE";
      };
      if (v instanceof CONNECT) {
          return "CONNECT";
      };
      if (v instanceof PROPFIND) {
          return "PROPFIND";
      };
      if (v instanceof PROPPATCH) {
          return "PROPPATCH";
      };
      if (v instanceof MKCOL) {
          return "MKCOL";
      };
      if (v instanceof COPY) {
          return "COPY";
      };
      if (v instanceof MOVE) {
          return "MOVE";
      };
      if (v instanceof LOCK) {
          return "LOCK";
      };
      if (v instanceof UNLOCK) {
          return "UNLOCK";
      };
      if (v instanceof PATCH) {
          return "PATCH";
      };
      throw new Error("Failed pattern match at Data.HTTP.Method (line 40, column 1 - line 56, column 23): " + [ v.constructor.name ]);
  });
  var print = Data_Either.either(Data_Show.show(showMethod))(unCustomMethod);
  exports["GET"] = GET;
  exports["POST"] = POST;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Plus"] = $PS["Control.Plus"] || {};
  var exports = $PS["Control.Plus"];                   
  var Plus = function (Alt0, empty) {
      this.Alt0 = Alt0;
      this.empty = empty;
  };       
  var empty = function (dict) {
      return dict.empty;
  };
  exports["Plus"] = Plus;
  exports["empty"] = empty;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.NonEmpty"] = $PS["Data.NonEmpty"] || {};
  var exports = $PS["Data.NonEmpty"];
  var Control_Plus = $PS["Control.Plus"];
  var Data_Show = $PS["Data.Show"];                              
  var NonEmpty = (function () {
      function NonEmpty(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      NonEmpty.create = function (value0) {
          return function (value1) {
              return new NonEmpty(value0, value1);
          };
      };
      return NonEmpty;
  })();
  var singleton = function (dictPlus) {
      return function (a) {
          return new NonEmpty(a, Control_Plus.empty(dictPlus));
      };
  };
  var showNonEmpty = function (dictShow) {
      return function (dictShow1) {
          return new Data_Show.Show(function (v) {
              return "(NonEmpty " + (Data_Show.show(dictShow)(v.value0) + (" " + (Data_Show.show(dictShow1)(v.value1) + ")")));
          });
      };
  };
  exports["singleton"] = singleton;
  exports["showNonEmpty"] = showNonEmpty;
})(PS);
(function(exports) {
  "use strict";

  exports.unfoldrArrayImpl = function (isNothing) {
    return function (fromJust) {
      return function (fst) {
        return function (snd) {
          return function (f) {
            return function (b) {
              var result = [];
              var value = b;
              while (true) { // eslint-disable-line no-constant-condition
                var maybe = f(value);
                if (isNothing(maybe)) return result;
                var tuple = fromJust(maybe);
                result.push(fst(tuple));
                value = snd(tuple);
              }
            };
          };
        };
      };
    };
  };
})(PS["Data.Unfoldable"] = PS["Data.Unfoldable"] || {});
(function(exports) {
  "use strict";

  exports.unfoldr1ArrayImpl = function (isNothing) {
    return function (fromJust) {
      return function (fst) {
        return function (snd) {
          return function (f) {
            return function (b) {
              var result = [];
              var value = b;
              while (true) { // eslint-disable-line no-constant-condition
                var tuple = f(value);
                result.push(fst(tuple));
                var maybe = snd(tuple);
                if (isNothing(maybe)) return result;
                value = fromJust(maybe);
              }
            };
          };
        };
      };
    };
  };
})(PS["Data.Unfoldable1"] = PS["Data.Unfoldable1"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Unfoldable1"] = $PS["Data.Unfoldable1"] || {};
  var exports = $PS["Data.Unfoldable1"];
  var $foreign = $PS["Data.Unfoldable1"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Tuple = $PS["Data.Tuple"];                
  var Unfoldable1 = function (unfoldr1) {
      this.unfoldr1 = unfoldr1;
  }; 
  var unfoldable1Array = new Unfoldable1($foreign.unfoldr1ArrayImpl(Data_Maybe.isNothing)(Data_Maybe.fromJust())(Data_Tuple.fst)(Data_Tuple.snd));
  exports["Unfoldable1"] = Unfoldable1;
  exports["unfoldable1Array"] = unfoldable1Array;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Unfoldable"] = $PS["Data.Unfoldable"] || {};
  var exports = $PS["Data.Unfoldable"];
  var $foreign = $PS["Data.Unfoldable"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unfoldable1 = $PS["Data.Unfoldable1"];  
  var Unfoldable = function (Unfoldable10, unfoldr) {
      this.Unfoldable10 = Unfoldable10;
      this.unfoldr = unfoldr;
  };
  var unfoldr = function (dict) {
      return dict.unfoldr;
  }; 
  var unfoldableArray = new Unfoldable(function () {
      return Data_Unfoldable1.unfoldable1Array;
  }, $foreign.unfoldrArrayImpl(Data_Maybe.isNothing)(Data_Maybe.fromJust())(Data_Tuple.fst)(Data_Tuple.snd));
  exports["Unfoldable"] = Unfoldable;
  exports["unfoldr"] = unfoldr;
  exports["unfoldableArray"] = unfoldableArray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.List.Types"] = $PS["Data.List.Types"] || {};
  var exports = $PS["Data.List.Types"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Plus = $PS["Control.Plus"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_NonEmpty = $PS["Data.NonEmpty"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Unfoldable = $PS["Data.Unfoldable"];
  var Data_Unfoldable1 = $PS["Data.Unfoldable1"];                
  var Nil = (function () {
      function Nil() {

      };
      Nil.value = new Nil();
      return Nil;
  })();
  var Cons = (function () {
      function Cons(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Cons.create = function (value0) {
          return function (value1) {
              return new Cons(value0, value1);
          };
      };
      return Cons;
  })();
  var NonEmptyList = function (x) {
      return x;
  };
  var listMap = function (f) {
      var chunkedRevMap = function ($copy_chunksAcc) {
          return function ($copy_v) {
              var $tco_var_chunksAcc = $copy_chunksAcc;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(chunksAcc, v) {
                  if (v instanceof Cons && (v.value1 instanceof Cons && v.value1.value1 instanceof Cons)) {
                      $tco_var_chunksAcc = new Cons(v, chunksAcc);
                      $copy_v = v.value1.value1.value1;
                      return;
                  };
                  var unrolledMap = function (v1) {
                      if (v1 instanceof Cons && (v1.value1 instanceof Cons && v1.value1.value1 instanceof Nil)) {
                          return new Cons(f(v1.value0), new Cons(f(v1.value1.value0), Nil.value));
                      };
                      if (v1 instanceof Cons && v1.value1 instanceof Nil) {
                          return new Cons(f(v1.value0), Nil.value);
                      };
                      return Nil.value;
                  };
                  var reverseUnrolledMap = function ($copy_v1) {
                      return function ($copy_acc) {
                          var $tco_var_v1 = $copy_v1;
                          var $tco_done = false;
                          var $tco_result;
                          function $tco_loop(v1, acc) {
                              if (v1 instanceof Cons && (v1.value0 instanceof Cons && (v1.value0.value1 instanceof Cons && v1.value0.value1.value1 instanceof Cons))) {
                                  $tco_var_v1 = v1.value1;
                                  $copy_acc = new Cons(f(v1.value0.value0), new Cons(f(v1.value0.value1.value0), new Cons(f(v1.value0.value1.value1.value0), acc)));
                                  return;
                              };
                              $tco_done = true;
                              return acc;
                          };
                          while (!$tco_done) {
                              $tco_result = $tco_loop($tco_var_v1, $copy_acc);
                          };
                          return $tco_result;
                      };
                  };
                  $tco_done = true;
                  return reverseUnrolledMap(chunksAcc)(unrolledMap(v));
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_chunksAcc, $copy_v);
              };
              return $tco_result;
          };
      };
      return chunkedRevMap(Nil.value);
  };
  var functorList = new Data_Functor.Functor(listMap);                 
  var foldableList = new Data_Foldable.Foldable(function (dictMonoid) {
      return function (f) {
          return Data_Foldable.foldl(foldableList)(function (acc) {
              var $202 = Data_Semigroup.append(dictMonoid.Semigroup0())(acc);
              return function ($203) {
                  return $202(f($203));
              };
          })(Data_Monoid.mempty(dictMonoid));
      };
  }, function (f) {
      var go = function ($copy_b) {
          return function ($copy_v) {
              var $tco_var_b = $copy_b;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(b, v) {
                  if (v instanceof Nil) {
                      $tco_done = true;
                      return b;
                  };
                  if (v instanceof Cons) {
                      $tco_var_b = f(b)(v.value0);
                      $copy_v = v.value1;
                      return;
                  };
                  throw new Error("Failed pattern match at Data.List.Types (line 109, column 12 - line 111, column 30): " + [ v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_b, $copy_v);
              };
              return $tco_result;
          };
      };
      return go;
  }, function (f) {
      return function (b) {
          var rev = Data_Foldable.foldl(foldableList)(Data_Function.flip(Cons.create))(Nil.value);
          var $204 = Data_Foldable.foldl(foldableList)(Data_Function.flip(f))(b);
          return function ($205) {
              return $204(rev($205));
          };
      };
  });
  var semigroupList = new Data_Semigroup.Semigroup(function (xs) {
      return function (ys) {
          return Data_Foldable.foldr(foldableList)(Cons.create)(ys)(xs);
      };
  });
  var showList = function (dictShow) {
      return new Data_Show.Show(function (v) {
          if (v instanceof Nil) {
              return "Nil";
          };
          return "(" + (Data_Foldable.intercalate(foldableList)(Data_Monoid.monoidString)(" : ")(Data_Functor.map(functorList)(Data_Show.show(dictShow))(v)) + " : Nil)");
      });
  };
  var showNonEmptyList = function (dictShow) {
      return new Data_Show.Show(function (v) {
          return "(NonEmptyList " + (Data_Show.show(Data_NonEmpty.showNonEmpty(dictShow)(showList(dictShow)))(v) + ")");
      });
  }; 
  var unfoldable1List = new Data_Unfoldable1.Unfoldable1(function (f) {
      return function (b) {
          var go = function ($copy_source) {
              return function ($copy_memo) {
                  var $tco_var_source = $copy_source;
                  var $tco_done = false;
                  var $tco_result;
                  function $tco_loop(source, memo) {
                      var v = f(source);
                      if (v.value1 instanceof Data_Maybe.Just) {
                          $tco_var_source = v.value1.value0;
                          $copy_memo = new Cons(v.value0, memo);
                          return;
                      };
                      if (v.value1 instanceof Data_Maybe.Nothing) {
                          $tco_done = true;
                          return Data_Foldable.foldl(foldableList)(Data_Function.flip(Cons.create))(Nil.value)(new Cons(v.value0, memo));
                      };
                      throw new Error("Failed pattern match at Data.List.Types (line 133, column 22 - line 135, column 61): " + [ v.constructor.name ]);
                  };
                  while (!$tco_done) {
                      $tco_result = $tco_loop($tco_var_source, $copy_memo);
                  };
                  return $tco_result;
              };
          };
          return go(b)(Nil.value);
      };
  });
  var unfoldableList = new Data_Unfoldable.Unfoldable(function () {
      return unfoldable1List;
  }, function (f) {
      return function (b) {
          var go = function ($copy_source) {
              return function ($copy_memo) {
                  var $tco_var_source = $copy_source;
                  var $tco_done = false;
                  var $tco_result;
                  function $tco_loop(source, memo) {
                      var v = f(source);
                      if (v instanceof Data_Maybe.Nothing) {
                          $tco_done = true;
                          return Data_Foldable.foldl(foldableList)(Data_Function.flip(Cons.create))(Nil.value)(memo);
                      };
                      if (v instanceof Data_Maybe.Just) {
                          $tco_var_source = v.value0.value1;
                          $copy_memo = new Cons(v.value0.value0, memo);
                          return;
                      };
                      throw new Error("Failed pattern match at Data.List.Types (line 140, column 22 - line 142, column 52): " + [ v.constructor.name ]);
                  };
                  while (!$tco_done) {
                      $tco_result = $tco_loop($tco_var_source, $copy_memo);
                  };
                  return $tco_result;
              };
          };
          return go(b)(Nil.value);
      };
  });
  var applyList = new Control_Apply.Apply(function () {
      return functorList;
  }, function (v) {
      return function (v1) {
          if (v instanceof Nil) {
              return Nil.value;
          };
          if (v instanceof Cons) {
              return Data_Semigroup.append(semigroupList)(Data_Functor.map(functorList)(v.value0)(v1))(Control_Apply.apply(applyList)(v.value1)(v1));
          };
          throw new Error("Failed pattern match at Data.List.Types (line 155, column 1 - line 157, column 48): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var applicativeList = new Control_Applicative.Applicative(function () {
      return applyList;
  }, function (a) {
      return new Cons(a, Nil.value);
  });                                              
  var altList = new Control_Alt.Alt(function () {
      return functorList;
  }, Data_Semigroup.append(semigroupList));
  var plusList = new Control_Plus.Plus(function () {
      return altList;
  }, Nil.value);
  exports["Nil"] = Nil;
  exports["Cons"] = Cons;
  exports["NonEmptyList"] = NonEmptyList;
  exports["semigroupList"] = semigroupList;
  exports["functorList"] = functorList;
  exports["foldableList"] = foldableList;
  exports["unfoldableList"] = unfoldableList;
  exports["applicativeList"] = applicativeList;
  exports["plusList"] = plusList;
  exports["showNonEmptyList"] = showNonEmptyList;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.List.NonEmpty"] = $PS["Data.List.NonEmpty"] || {};
  var exports = $PS["Data.List.NonEmpty"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_NonEmpty = $PS["Data.NonEmpty"];
  var singleton = (function () {
      var $168 = Data_NonEmpty.singleton(Data_List_Types.plusList);
      return function ($169) {
          return Data_List_Types.NonEmptyList($168($169));
      };
  })();
  var head = function (v) {
      return v.value0;
  };
  exports["singleton"] = singleton;
  exports["head"] = head;
})(PS);
(function(exports) {
  "use strict";

  exports["null"] = null;

  exports.nullable = function (a, r, f) {
    return a == null ? r : f(a);
  };

  exports.notNull = function (x) {
    return x;
  };
})(PS["Data.Nullable"] = PS["Data.Nullable"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Nullable"] = $PS["Data.Nullable"] || {};
  var exports = $PS["Data.Nullable"];
  var $foreign = $PS["Data.Nullable"];
  var Data_Maybe = $PS["Data.Maybe"];              
  var toNullable = Data_Maybe.maybe($foreign["null"])($foreign.notNull);
  var toMaybe = function (n) {
      return $foreign.nullable(n, Data_Maybe.Nothing.value, Data_Maybe.Just.create);
  };
  exports["toMaybe"] = toMaybe;
  exports["toNullable"] = toNullable;
})(PS);
(function(exports) {
  /* globals setImmediate, clearImmediate, setTimeout, clearTimeout */
  /* jshint -W083, -W098, -W003 */
  "use strict";

  var Aff = function () {
    // A unique value for empty.
    var EMPTY = {};

    /*

  An awkward approximation. We elide evidence we would otherwise need in PS for
  efficiency sake.

  data Aff eff a
    = Pure a
    | Throw Error
    | Catch (Aff eff a) (Error -> Aff eff a)
    | Sync (Eff eff a)
    | Async ((Either Error a -> Eff eff Unit) -> Eff eff (Canceler eff))
    | forall b. Bind (Aff eff b) (b -> Aff eff a)
    | forall b. Bracket (Aff eff b) (BracketConditions eff b) (b -> Aff eff a)
    | forall b. Fork Boolean (Aff eff b) ?(Fiber eff b -> a)
    | Sequential (ParAff aff a)

  */  
    var PURE    = "Pure";
    var THROW   = "Throw";
    var CATCH   = "Catch";
    var SYNC    = "Sync";
    var ASYNC   = "Async";
    var BIND    = "Bind";
    var BRACKET = "Bracket";
    var FORK    = "Fork";
    var SEQ     = "Sequential";

    /*

  data ParAff eff a
    = forall b. Map (b -> a) (ParAff eff b)
    | forall b. Apply (ParAff eff (b -> a)) (ParAff eff b)
    | Alt (ParAff eff a) (ParAff eff a)
    | ?Par (Aff eff a)

  */  
    var MAP   = "Map";
    var APPLY = "Apply";
    var ALT   = "Alt";

    // Various constructors used in interpretation
    var CONS      = "Cons";      // Cons-list, for stacks
    var RESUME    = "Resume";    // Continue indiscriminately
    var RELEASE   = "Release";   // Continue with bracket finalizers
    var FINALIZER = "Finalizer"; // A non-interruptible effect
    var FINALIZED = "Finalized"; // Marker for finalization
    var FORKED    = "Forked";    // Reference to a forked fiber, with resumption stack
    var FIBER     = "Fiber";     // Actual fiber reference
    var THUNK     = "Thunk";     // Primed effect, ready to invoke

    function Aff(tag, _1, _2, _3) {
      this.tag = tag;
      this._1  = _1;
      this._2  = _2;
      this._3  = _3;
    }

    function AffCtr(tag) {
      var fn = function (_1, _2, _3) {
        return new Aff(tag, _1, _2, _3);
      };
      fn.tag = tag;
      return fn;
    }

    function nonCanceler(error) {
      return new Aff(PURE, void 0);
    }

    function runEff(eff) {
      try {
        eff();
      } catch (error) {
        setTimeout(function () {
          throw error;
        }, 0);
      }
    }

    function runSync(left, right, eff) {
      try {
        return right(eff());
      } catch (error) {
        return left(error);
      }
    }

    function runAsync(left, eff, k) {
      try {
        return eff(k)();
      } catch (error) {
        k(left(error))();
        return nonCanceler;
      }
    }

    var Scheduler = function () {
      var limit    = 1024;
      var size     = 0;
      var ix       = 0;
      var queue    = new Array(limit);
      var draining = false;

      function drain() {
        var thunk;
        draining = true;
        while (size !== 0) {
          size--;
          thunk     = queue[ix];
          queue[ix] = void 0;
          ix        = (ix + 1) % limit;
          thunk();
        }
        draining = false;
      }

      return {
        isDraining: function () {
          return draining;
        },
        enqueue: function (cb) {
          var i, tmp;
          if (size === limit) {
            tmp = draining;
            drain();
            draining = tmp;
          }

          queue[(ix + size) % limit] = cb;
          size++;

          if (!draining) {
            drain();
          }
        }
      };
    }();

    function Supervisor(util) {
      var fibers  = {};
      var fiberId = 0;
      var count   = 0;

      return {
        register: function (fiber) {
          var fid = fiberId++;
          fiber.onComplete({
            rethrow: true,
            handler: function (result) {
              return function () {
                count--;
                delete fibers[fid];
              };
            }
          })();
          fibers[fid] = fiber;
          count++;
        },
        isEmpty: function () {
          return count === 0;
        },
        killAll: function (killError, cb) {
          return function () {
            if (count === 0) {
              return cb();
            }

            var killCount = 0;
            var kills     = {};

            function kill(fid) {
              kills[fid] = fibers[fid].kill(killError, function (result) {
                return function () {
                  delete kills[fid];
                  killCount--;
                  if (util.isLeft(result) && util.fromLeft(result)) {
                    setTimeout(function () {
                      throw util.fromLeft(result);
                    }, 0);
                  }
                  if (killCount === 0) {
                    cb();
                  }
                };
              })();
            }

            for (var k in fibers) {
              if (fibers.hasOwnProperty(k)) {
                killCount++;
                kill(k);
              }
            }

            fibers  = {};
            fiberId = 0;
            count   = 0;

            return function (error) {
              return new Aff(SYNC, function () {
                for (var k in kills) {
                  if (kills.hasOwnProperty(k)) {
                    kills[k]();
                  }
                }
              });
            };
          };
        }
      };
    }

    // Fiber state machine
    var SUSPENDED   = 0; // Suspended, pending a join.
    var CONTINUE    = 1; // Interpret the next instruction.
    var STEP_BIND   = 2; // Apply the next bind.
    var STEP_RESULT = 3; // Handle potential failure from a result.
    var PENDING     = 4; // An async effect is running.
    var RETURN      = 5; // The current stack has returned.
    var COMPLETED   = 6; // The entire fiber has completed.

    function Fiber(util, supervisor, aff) {
      // Monotonically increasing tick, increased on each asynchronous turn.
      var runTick = 0;

      // The current branch of the state machine.
      var status = SUSPENDED;

      // The current point of interest for the state machine branch.
      var step      = aff;  // Successful step
      var fail      = null; // Failure step
      var interrupt = null; // Asynchronous interrupt

      // Stack of continuations for the current fiber.
      var bhead = null;
      var btail = null;

      // Stack of attempts and finalizers for error recovery. Every `Cons` is also
      // tagged with current `interrupt` state. We use this to track which items
      // should be ignored or evaluated as a result of a kill.
      var attempts = null;

      // A special state is needed for Bracket, because it cannot be killed. When
      // we enter a bracket acquisition or finalizer, we increment the counter,
      // and then decrement once complete.
      var bracketCount = 0;

      // Each join gets a new id so they can be revoked.
      var joinId  = 0;
      var joins   = null;
      var rethrow = true;

      // Each invocation of `run` requires a tick. When an asynchronous effect is
      // resolved, we must check that the local tick coincides with the fiber
      // tick before resuming. This prevents multiple async continuations from
      // accidentally resuming the same fiber. A common example may be invoking
      // the provided callback in `makeAff` more than once, but it may also be an
      // async effect resuming after the fiber was already cancelled.
      function run(localRunTick) {
        var tmp, result, attempt;
        while (true) {
          tmp       = null;
          result    = null;
          attempt   = null;

          switch (status) {
          case STEP_BIND:
            status = CONTINUE;
            try {
              step   = bhead(step);
              if (btail === null) {
                bhead = null;
              } else {
                bhead = btail._1;
                btail = btail._2;
              }
            } catch (e) {
              status = RETURN;
              fail   = util.left(e);
              step   = null;
            }
            break;

          case STEP_RESULT:
            if (util.isLeft(step)) {
              status = RETURN;
              fail   = step;
              step   = null;
            } else if (bhead === null) {
              status = RETURN;
            } else {
              status = STEP_BIND;
              step   = util.fromRight(step);
            }
            break;

          case CONTINUE:
            switch (step.tag) {
            case BIND:
              if (bhead) {
                btail = new Aff(CONS, bhead, btail);
              }
              bhead  = step._2;
              status = CONTINUE;
              step   = step._1;
              break;

            case PURE:
              if (bhead === null) {
                status = RETURN;
                step   = util.right(step._1);
              } else {
                status = STEP_BIND;
                step   = step._1;
              }
              break;

            case SYNC:
              status = STEP_RESULT;
              step   = runSync(util.left, util.right, step._1);
              break;

            case ASYNC:
              status = PENDING;
              step   = runAsync(util.left, step._1, function (result) {
                return function () {
                  if (runTick !== localRunTick) {
                    return;
                  }
                  runTick++;
                  Scheduler.enqueue(function () {
                    // It's possible to interrupt the fiber between enqueuing and
                    // resuming, so we need to check that the runTick is still
                    // valid.
                    if (runTick !== localRunTick + 1) {
                      return;
                    }
                    status = STEP_RESULT;
                    step   = result;
                    run(runTick);
                  });
                };
              });
              return;

            case THROW:
              status = RETURN;
              fail   = util.left(step._1);
              step   = null;
              break;

            // Enqueue the Catch so that we can call the error handler later on
            // in case of an exception.
            case CATCH:
              if (bhead === null) {
                attempts = new Aff(CONS, step, attempts, interrupt);
              } else {
                attempts = new Aff(CONS, step, new Aff(CONS, new Aff(RESUME, bhead, btail), attempts, interrupt), interrupt);
              }
              bhead    = null;
              btail    = null;
              status   = CONTINUE;
              step     = step._1;
              break;

            // Enqueue the Bracket so that we can call the appropriate handlers
            // after resource acquisition.
            case BRACKET:
              bracketCount++;
              if (bhead === null) {
                attempts = new Aff(CONS, step, attempts, interrupt);
              } else {
                attempts = new Aff(CONS, step, new Aff(CONS, new Aff(RESUME, bhead, btail), attempts, interrupt), interrupt);
              }
              bhead  = null;
              btail  = null;
              status = CONTINUE;
              step   = step._1;
              break;

            case FORK:
              status = STEP_RESULT;
              tmp    = Fiber(util, supervisor, step._2);
              if (supervisor) {
                supervisor.register(tmp);
              }
              if (step._1) {
                tmp.run();
              }
              step = util.right(tmp);
              break;

            case SEQ:
              status = CONTINUE;
              step   = sequential(util, supervisor, step._1);
              break;
            }
            break;

          case RETURN:
            bhead = null;
            btail = null;
            // If the current stack has returned, and we have no other stacks to
            // resume or finalizers to run, the fiber has halted and we can
            // invoke all join callbacks. Otherwise we need to resume.
            if (attempts === null) {
              status = COMPLETED;
              step   = interrupt || fail || step;
            } else {
              // The interrupt status for the enqueued item.
              tmp      = attempts._3;
              attempt  = attempts._1;
              attempts = attempts._2;

              switch (attempt.tag) {
              // We cannot recover from an unmasked interrupt. Otherwise we should
              // continue stepping, or run the exception handler if an exception
              // was raised.
              case CATCH:
                // We should compare the interrupt status as well because we
                // only want it to apply if there has been an interrupt since
                // enqueuing the catch.
                if (interrupt && interrupt !== tmp && bracketCount === 0) {
                  status = RETURN;
                } else if (fail) {
                  status = CONTINUE;
                  step   = attempt._2(util.fromLeft(fail));
                  fail   = null;
                }
                break;

              // We cannot resume from an unmasked interrupt or exception.
              case RESUME:
                // As with Catch, we only want to ignore in the case of an
                // interrupt since enqueing the item.
                if (interrupt && interrupt !== tmp && bracketCount === 0 || fail) {
                  status = RETURN;
                } else {
                  bhead  = attempt._1;
                  btail  = attempt._2;
                  status = STEP_BIND;
                  step   = util.fromRight(step);
                }
                break;

              // If we have a bracket, we should enqueue the handlers,
              // and continue with the success branch only if the fiber has
              // not been interrupted. If the bracket acquisition failed, we
              // should not run either.
              case BRACKET:
                bracketCount--;
                if (fail === null) {
                  result   = util.fromRight(step);
                  // We need to enqueue the Release with the same interrupt
                  // status as the Bracket that is initiating it.
                  attempts = new Aff(CONS, new Aff(RELEASE, attempt._2, result), attempts, tmp);
                  // We should only coninue as long as the interrupt status has not changed or
                  // we are currently within a non-interruptable finalizer.
                  if (interrupt === tmp || bracketCount > 0) {
                    status = CONTINUE;
                    step   = attempt._3(result);
                  }
                }
                break;

              // Enqueue the appropriate handler. We increase the bracket count
              // because it should not be cancelled.
              case RELEASE:
                attempts = new Aff(CONS, new Aff(FINALIZED, step, fail), attempts, interrupt);
                status   = CONTINUE;
                // It has only been killed if the interrupt status has changed
                // since we enqueued the item, and the bracket count is 0. If the
                // bracket count is non-zero then we are in a masked state so it's
                // impossible to be killed.
                if (interrupt && interrupt !== tmp && bracketCount === 0) {
                  step = attempt._1.killed(util.fromLeft(interrupt))(attempt._2);
                } else if (fail) {
                  step = attempt._1.failed(util.fromLeft(fail))(attempt._2);
                } else {
                  step = attempt._1.completed(util.fromRight(step))(attempt._2);
                }
                fail = null;
                bracketCount++;
                break;

              case FINALIZER:
                bracketCount++;
                attempts = new Aff(CONS, new Aff(FINALIZED, step, fail), attempts, interrupt);
                status   = CONTINUE;
                step     = attempt._1;
                break;

              case FINALIZED:
                bracketCount--;
                status = RETURN;
                step   = attempt._1;
                fail   = attempt._2;
                break;
              }
            }
            break;

          case COMPLETED:
            for (var k in joins) {
              if (joins.hasOwnProperty(k)) {
                rethrow = rethrow && joins[k].rethrow;
                runEff(joins[k].handler(step));
              }
            }
            joins = null;
            // If we have an interrupt and a fail, then the thread threw while
            // running finalizers. This should always rethrow in a fresh stack.
            if (interrupt && fail) {
              setTimeout(function () {
                throw util.fromLeft(fail);
              }, 0);
            // If we have an unhandled exception, and no other fiber has joined
            // then we need to throw the exception in a fresh stack.
            } else if (util.isLeft(step) && rethrow) {
              setTimeout(function () {
                // Guard on reathrow because a completely synchronous fiber can
                // still have an observer which was added after-the-fact.
                if (rethrow) {
                  throw util.fromLeft(step);
                }
              }, 0);
            }
            return;
          case SUSPENDED:
            status = CONTINUE;
            break;
          case PENDING: return;
          }
        }
      }

      function onComplete(join) {
        return function () {
          if (status === COMPLETED) {
            rethrow = rethrow && join.rethrow;
            join.handler(step)();
            return function () {};
          }

          var jid    = joinId++;
          joins      = joins || {};
          joins[jid] = join;

          return function() {
            if (joins !== null) {
              delete joins[jid];
            }
          };
        };
      }

      function kill(error, cb) {
        return function () {
          if (status === COMPLETED) {
            cb(util.right(void 0))();
            return function () {};
          }

          var canceler = onComplete({
            rethrow: false,
            handler: function (/* unused */) {
              return cb(util.right(void 0));
            }
          })();

          switch (status) {
          case SUSPENDED:
            interrupt = util.left(error);
            status    = COMPLETED;
            step      = interrupt;
            run(runTick);
            break;
          case PENDING:
            if (interrupt === null) {
              interrupt = util.left(error);
            }
            if (bracketCount === 0) {
              if (status === PENDING) {
                attempts = new Aff(CONS, new Aff(FINALIZER, step(error)), attempts, interrupt);
              }
              status   = RETURN;
              step     = null;
              fail     = null;
              run(++runTick);
            }
            break;
          default:
            if (interrupt === null) {
              interrupt = util.left(error);
            }
            if (bracketCount === 0) {
              status = RETURN;
              step   = null;
              fail   = null;
            }
          }

          return canceler;
        };
      }

      function join(cb) {
        return function () {
          var canceler = onComplete({
            rethrow: false,
            handler: cb
          })();
          if (status === SUSPENDED) {
            run(runTick);
          }
          return canceler;
        };
      }

      return {
        kill: kill,
        join: join,
        onComplete: onComplete,
        isSuspended: function () {
          return status === SUSPENDED;
        },
        run: function () {
          if (status === SUSPENDED) {
            if (!Scheduler.isDraining()) {
              Scheduler.enqueue(function () {
                run(runTick);
              });
            } else {
              run(runTick);
            }
          }
        }
      };
    }

    function runPar(util, supervisor, par, cb) {
      // Table of all forked fibers.
      var fiberId   = 0;
      var fibers    = {};

      // Table of currently running cancelers, as a product of `Alt` behavior.
      var killId    = 0;
      var kills     = {};

      // Error used for early cancelation on Alt branches.
      var early     = new Error("[ParAff] Early exit");

      // Error used to kill the entire tree.
      var interrupt = null;

      // The root pointer of the tree.
      var root      = EMPTY;

      // Walks a tree, invoking all the cancelers. Returns the table of pending
      // cancellation fibers.
      function kill(error, par, cb) {
        var step  = par;
        var head  = null;
        var tail  = null;
        var count = 0;
        var kills = {};
        var tmp, kid;

        loop: while (true) {
          tmp = null;

          switch (step.tag) {
          case FORKED:
            if (step._3 === EMPTY) {
              tmp = fibers[step._1];
              kills[count++] = tmp.kill(error, function (result) {
                return function () {
                  count--;
                  if (count === 0) {
                    cb(result)();
                  }
                };
              });
            }
            // Terminal case.
            if (head === null) {
              break loop;
            }
            // Go down the right side of the tree.
            step = head._2;
            if (tail === null) {
              head = null;
            } else {
              head = tail._1;
              tail = tail._2;
            }
            break;
          case MAP:
            step = step._2;
            break;
          case APPLY:
          case ALT:
            if (head) {
              tail = new Aff(CONS, head, tail);
            }
            head = step;
            step = step._1;
            break;
          }
        }

        if (count === 0) {
          cb(util.right(void 0))();
        } else {
          // Run the cancelation effects. We alias `count` because it's mutable.
          kid = 0;
          tmp = count;
          for (; kid < tmp; kid++) {
            kills[kid] = kills[kid]();
          }
        }

        return kills;
      }

      // When a fiber resolves, we need to bubble back up the tree with the
      // result, computing the applicative nodes.
      function join(result, head, tail) {
        var fail, step, lhs, rhs, tmp, kid;

        if (util.isLeft(result)) {
          fail = result;
          step = null;
        } else {
          step = result;
          fail = null;
        }

        loop: while (true) {
          lhs = null;
          rhs = null;
          tmp = null;
          kid = null;

          // We should never continue if the entire tree has been interrupted.
          if (interrupt !== null) {
            return;
          }

          // We've made it all the way to the root of the tree, which means
          // the tree has fully evaluated.
          if (head === null) {
            cb(fail || step)();
            return;
          }

          // The tree has already been computed, so we shouldn't try to do it
          // again. This should never happen.
          // TODO: Remove this?
          if (head._3 !== EMPTY) {
            return;
          }

          switch (head.tag) {
          case MAP:
            if (fail === null) {
              head._3 = util.right(head._1(util.fromRight(step)));
              step    = head._3;
            } else {
              head._3 = fail;
            }
            break;
          case APPLY:
            lhs = head._1._3;
            rhs = head._2._3;
            // If we have a failure we should kill the other side because we
            // can't possible yield a result anymore.
            if (fail) {
              head._3 = fail;
              tmp     = true;
              kid     = killId++;

              kills[kid] = kill(early, fail === lhs ? head._2 : head._1, function (/* unused */) {
                return function () {
                  delete kills[kid];
                  if (tmp) {
                    tmp = false;
                  } else if (tail === null) {
                    join(fail, null, null);
                  } else {
                    join(fail, tail._1, tail._2);
                  }
                };
              });

              if (tmp) {
                tmp = false;
                return;
              }
            } else if (lhs === EMPTY || rhs === EMPTY) {
              // We can only proceed if both sides have resolved.
              return;
            } else {
              step    = util.right(util.fromRight(lhs)(util.fromRight(rhs)));
              head._3 = step;
            }
            break;
          case ALT:
            lhs = head._1._3;
            rhs = head._2._3;
            // We can only proceed if both have resolved or we have a success
            if (lhs === EMPTY && util.isLeft(rhs) || rhs === EMPTY && util.isLeft(lhs)) {
              return;
            }
            // If both sides resolve with an error, we should continue with the
            // first error
            if (lhs !== EMPTY && util.isLeft(lhs) && rhs !== EMPTY && util.isLeft(rhs)) {
              fail    = step === lhs ? rhs : lhs;
              step    = null;
              head._3 = fail;
            } else {
              head._3 = step;
              tmp     = true;
              kid     = killId++;
              // Once a side has resolved, we need to cancel the side that is still
              // pending before we can continue.
              kills[kid] = kill(early, step === lhs ? head._2 : head._1, function (/* unused */) {
                return function () {
                  delete kills[kid];
                  if (tmp) {
                    tmp = false;
                  } else if (tail === null) {
                    join(step, null, null);
                  } else {
                    join(step, tail._1, tail._2);
                  }
                };
              });

              if (tmp) {
                tmp = false;
                return;
              }
            }
            break;
          }

          if (tail === null) {
            head = null;
          } else {
            head = tail._1;
            tail = tail._2;
          }
        }
      }

      function resolve(fiber) {
        return function (result) {
          return function () {
            delete fibers[fiber._1];
            fiber._3 = result;
            join(result, fiber._2._1, fiber._2._2);
          };
        };
      }

      // Walks the applicative tree, substituting non-applicative nodes with
      // `FORKED` nodes. In this tree, all applicative nodes use the `_3` slot
      // as a mutable slot for memoization. In an unresolved state, the `_3`
      // slot is `EMPTY`. In the cases of `ALT` and `APPLY`, we always walk
      // the left side first, because both operations are left-associative. As
      // we `RETURN` from those branches, we then walk the right side.
      function run() {
        var status = CONTINUE;
        var step   = par;
        var head   = null;
        var tail   = null;
        var tmp, fid;

        loop: while (true) {
          tmp = null;
          fid = null;

          switch (status) {
          case CONTINUE:
            switch (step.tag) {
            case MAP:
              if (head) {
                tail = new Aff(CONS, head, tail);
              }
              head = new Aff(MAP, step._1, EMPTY, EMPTY);
              step = step._2;
              break;
            case APPLY:
              if (head) {
                tail = new Aff(CONS, head, tail);
              }
              head = new Aff(APPLY, EMPTY, step._2, EMPTY);
              step = step._1;
              break;
            case ALT:
              if (head) {
                tail = new Aff(CONS, head, tail);
              }
              head = new Aff(ALT, EMPTY, step._2, EMPTY);
              step = step._1;
              break;
            default:
              // When we hit a leaf value, we suspend the stack in the `FORKED`.
              // When the fiber resolves, it can bubble back up the tree.
              fid    = fiberId++;
              status = RETURN;
              tmp    = step;
              step   = new Aff(FORKED, fid, new Aff(CONS, head, tail), EMPTY);
              tmp    = Fiber(util, supervisor, tmp);
              tmp.onComplete({
                rethrow: false,
                handler: resolve(step)
              })();
              fibers[fid] = tmp;
              if (supervisor) {
                supervisor.register(tmp);
              }
            }
            break;
          case RETURN:
            // Terminal case, we are back at the root.
            if (head === null) {
              break loop;
            }
            // If we are done with the right side, we need to continue down the
            // left. Otherwise we should continue up the stack.
            if (head._1 === EMPTY) {
              head._1 = step;
              status  = CONTINUE;
              step    = head._2;
              head._2 = EMPTY;
            } else {
              head._2 = step;
              step    = head;
              if (tail === null) {
                head  = null;
              } else {
                head  = tail._1;
                tail  = tail._2;
              }
            }
          }
        }

        // Keep a reference to the tree root so it can be cancelled.
        root = step;

        for (fid = 0; fid < fiberId; fid++) {
          fibers[fid].run();
        }
      }

      // Cancels the entire tree. If there are already subtrees being canceled,
      // we need to first cancel those joins. We will then add fresh joins for
      // all pending branches including those that were in the process of being
      // canceled.
      function cancel(error, cb) {
        interrupt = util.left(error);
        var innerKills;
        for (var kid in kills) {
          if (kills.hasOwnProperty(kid)) {
            innerKills = kills[kid];
            for (kid in innerKills) {
              if (innerKills.hasOwnProperty(kid)) {
                innerKills[kid]();
              }
            }
          }
        }

        kills = null;
        var newKills = kill(error, root, cb);

        return function (killError) {
          return new Aff(ASYNC, function (killCb) {
            return function () {
              for (var kid in newKills) {
                if (newKills.hasOwnProperty(kid)) {
                  newKills[kid]();
                }
              }
              return nonCanceler;
            };
          });
        };
      }

      run();

      return function (killError) {
        return new Aff(ASYNC, function (killCb) {
          return function () {
            return cancel(killError, killCb);
          };
        });
      };
    }

    function sequential(util, supervisor, par) {
      return new Aff(ASYNC, function (cb) {
        return function () {
          return runPar(util, supervisor, par, cb);
        };
      });
    }

    Aff.EMPTY       = EMPTY;
    Aff.Pure        = AffCtr(PURE);
    Aff.Throw       = AffCtr(THROW);
    Aff.Catch       = AffCtr(CATCH);
    Aff.Sync        = AffCtr(SYNC);
    Aff.Async       = AffCtr(ASYNC);
    Aff.Bind        = AffCtr(BIND);
    Aff.Bracket     = AffCtr(BRACKET);
    Aff.Fork        = AffCtr(FORK);
    Aff.Seq         = AffCtr(SEQ);
    Aff.ParMap      = AffCtr(MAP);
    Aff.ParApply    = AffCtr(APPLY);
    Aff.ParAlt      = AffCtr(ALT);
    Aff.Fiber       = Fiber;
    Aff.Supervisor  = Supervisor;
    Aff.Scheduler   = Scheduler;
    Aff.nonCanceler = nonCanceler;

    return Aff;
  }();

  exports._pure = Aff.Pure;

  exports._throwError = Aff.Throw;

  exports._catchError = function (aff) {
    return function (k) {
      return Aff.Catch(aff, k);
    };
  };

  exports._map = function (f) {
    return function (aff) {
      if (aff.tag === Aff.Pure.tag) {
        return Aff.Pure(f(aff._1));
      } else {
        return Aff.Bind(aff, function (value) {
          return Aff.Pure(f(value));
        });
      }
    };
  };

  exports._bind = function (aff) {
    return function (k) {
      return Aff.Bind(aff, k);
    };
  };

  exports._liftEffect = Aff.Sync;

  exports.makeAff = Aff.Async;

  exports.generalBracket = function (acquire) {
    return function (options) {
      return function (k) {
        return Aff.Bracket(acquire, options, k);
      };
    };
  };

  exports._makeFiber = function (util, aff) {
    return function () {
      return Aff.Fiber(util, null, aff);
    };
  };
})(PS["Effect.Aff"] = PS["Effect.Aff"] || {});
(function(exports) {
  "use strict";

  exports.pureE = function (a) {
    return function () {
      return a;
    };
  };

  exports.bindE = function (a) {
    return function (f) {
      return function () {
        return f(a())();
      };
    };
  };
})(PS["Effect"] = PS["Effect"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect"] = $PS["Effect"] || {};
  var exports = $PS["Effect"];
  var $foreign = $PS["Effect"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Data_Functor = $PS["Data.Functor"];                    
  var monadEffect = new Control_Monad.Monad(function () {
      return applicativeEffect;
  }, function () {
      return bindEffect;
  });
  var bindEffect = new Control_Bind.Bind(function () {
      return applyEffect;
  }, $foreign.bindE);
  var applyEffect = new Control_Apply.Apply(function () {
      return functorEffect;
  }, Control_Monad.ap(monadEffect));
  var applicativeEffect = new Control_Applicative.Applicative(function () {
      return applyEffect;
  }, $foreign.pureE);
  var functorEffect = new Data_Functor.Functor(Control_Applicative.liftA1(applicativeEffect));
  exports["functorEffect"] = functorEffect;
  exports["applicativeEffect"] = applicativeEffect;
  exports["bindEffect"] = bindEffect;
  exports["monadEffect"] = monadEffect;
})(PS);
(function(exports) {
  "use strict";

  // module Partial.Unsafe

  exports.unsafePartial = function (f) {
    return f();
  };
})(PS["Partial.Unsafe"] = PS["Partial.Unsafe"] || {});
(function(exports) {
  "use strict";

  // module Partial

  exports.crashWith = function () {
    return function (msg) {
      throw new Error(msg);
    };
  };
})(PS["Partial"] = PS["Partial"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Partial"] = $PS["Partial"] || {};
  var exports = $PS["Partial"];
  var $foreign = $PS["Partial"];
  exports["crashWith"] = $foreign.crashWith;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Partial.Unsafe"] = $PS["Partial.Unsafe"] || {};
  var exports = $PS["Partial.Unsafe"];
  var $foreign = $PS["Partial.Unsafe"];
  var Partial = $PS["Partial"];
  var unsafeCrashWith = function (msg) {
      return $foreign.unsafePartial(function (dictPartial) {
          return Partial.crashWith()(msg);
      });
  };
  exports["unsafeCrashWith"] = unsafeCrashWith;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Aff"] = $PS["Effect.Aff"] || {};
  var exports = $PS["Effect.Aff"];
  var $foreign = $PS["Effect.Aff"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect = $PS["Effect"];
  var Effect_Class = $PS["Effect.Class"];
  var Partial_Unsafe = $PS["Partial.Unsafe"];                          
  var functorAff = new Data_Functor.Functor($foreign["_map"]);
  var ffiUtil = (function () {
      var unsafeFromRight = function (v) {
          if (v instanceof Data_Either.Right) {
              return v.value0;
          };
          if (v instanceof Data_Either.Left) {
              return Partial_Unsafe.unsafeCrashWith("unsafeFromRight: Left");
          };
          throw new Error("Failed pattern match at Effect.Aff (line 400, column 21 - line 402, column 54): " + [ v.constructor.name ]);
      };
      var unsafeFromLeft = function (v) {
          if (v instanceof Data_Either.Left) {
              return v.value0;
          };
          if (v instanceof Data_Either.Right) {
              return Partial_Unsafe.unsafeCrashWith("unsafeFromLeft: Right");
          };
          throw new Error("Failed pattern match at Effect.Aff (line 395, column 20 - line 397, column 54): " + [ v.constructor.name ]);
      };
      var isLeft = function (v) {
          if (v instanceof Data_Either.Left) {
              return true;
          };
          if (v instanceof Data_Either.Right) {
              return false;
          };
          throw new Error("Failed pattern match at Effect.Aff (line 390, column 12 - line 392, column 20): " + [ v.constructor.name ]);
      };
      return {
          isLeft: isLeft,
          fromLeft: unsafeFromLeft,
          fromRight: unsafeFromRight,
          left: Data_Either.Left.create,
          right: Data_Either.Right.create
      };
  })();
  var makeFiber = function (aff) {
      return $foreign["_makeFiber"](ffiUtil, aff);
  };
  var launchAff = function (aff) {
      return function __do() {
          var fiber = makeFiber(aff)();
          fiber.run();
          return fiber;
      };
  };
  var launchAff_ = (function () {
      var $43 = Data_Functor["void"](Effect.functorEffect);
      return function ($44) {
          return $43(launchAff($44));
      };
  })();
  var bracket = function (acquire) {
      return function (completed) {
          return $foreign.generalBracket(acquire)({
              killed: Data_Function["const"](completed),
              failed: Data_Function["const"](completed),
              completed: Data_Function["const"](completed)
          });
      };
  };
  var monadAff = new Control_Monad.Monad(function () {
      return applicativeAff;
  }, function () {
      return bindAff;
  });
  var bindAff = new Control_Bind.Bind(function () {
      return applyAff;
  }, $foreign["_bind"]);
  var applyAff = new Control_Apply.Apply(function () {
      return functorAff;
  }, Control_Monad.ap(monadAff));
  var applicativeAff = new Control_Applicative.Applicative(function () {
      return applyAff;
  }, $foreign["_pure"]);
  var monadEffectAff = new Effect_Class.MonadEffect(function () {
      return monadAff;
  }, $foreign["_liftEffect"]);
  var monadThrowAff = new Control_Monad_Error_Class.MonadThrow(function () {
      return monadAff;
  }, $foreign["_throwError"]);
  var monadErrorAff = new Control_Monad_Error_Class.MonadError(function () {
      return monadThrowAff;
  }, $foreign["_catchError"]);                                  
  var runAff = function (k) {
      return function (aff) {
          return launchAff(Control_Bind.bindFlipped(bindAff)((function () {
              var $49 = Effect_Class.liftEffect(monadEffectAff);
              return function ($50) {
                  return $49(k($50));
              };
          })())(Control_Monad_Error_Class["try"](monadErrorAff)(aff)));
      };
  };
  var nonCanceler = Data_Function["const"](Control_Applicative.pure(applicativeAff)(Data_Unit.unit));
  exports["launchAff_"] = launchAff_;
  exports["runAff"] = runAff;
  exports["bracket"] = bracket;
  exports["nonCanceler"] = nonCanceler;
  exports["functorAff"] = functorAff;
  exports["applicativeAff"] = applicativeAff;
  exports["bindAff"] = bindAff;
  exports["monadAff"] = monadAff;
  exports["monadThrowAff"] = monadThrowAff;
  exports["monadErrorAff"] = monadErrorAff;
  exports["monadEffectAff"] = monadEffectAff;
  exports["makeAff"] = $foreign.makeAff;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Aff.Compat"] = $PS["Effect.Aff.Compat"] || {};
  var exports = $PS["Effect.Aff.Compat"];
  var Data_Either = $PS["Data.Either"];
  var Effect_Aff = $PS["Effect.Aff"];
  var fromEffectFnAff = function (v) {
      return Effect_Aff.makeAff(function (k) {
          return function __do() {
              var v1 = v(function ($4) {
                  return k(Data_Either.Left.create($4))();
              }, function ($5) {
                  return k(Data_Either.Right.create($5))();
              });
              return function (e) {
                  return Effect_Aff.makeAff(function (k2) {
                      return function __do() {
                          v1(e, function ($6) {
                              return k2(Data_Either.Left.create($6))();
                          }, function ($7) {
                              return k2(Data_Either.Right.create($7))();
                          });
                          return Effect_Aff.nonCanceler;
                      };
                  });
              };
          };
      });
  };
  exports["fromEffectFnAff"] = fromEffectFnAff;
})(PS);
(function(exports) {
  "use strict";

  exports.showErrorImpl = function (err) {
    return err.stack || err.toString();
  };

  exports.error = function (msg) {
    return new Error(msg);
  };

  exports.message = function (e) {
    return e.message;
  };

  exports.throwException = function (e) {
    return function () {
      throw e;
    };
  };
})(PS["Effect.Exception"] = PS["Effect.Exception"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Exception"] = $PS["Effect.Exception"] || {};
  var exports = $PS["Effect.Exception"];
  var $foreign = $PS["Effect.Exception"];
  var Data_Show = $PS["Data.Show"];
  var $$throw = function ($2) {
      return $foreign.throwException($foreign.error($2));
  };                                                                               
  var showError = new Data_Show.Show($foreign.showErrorImpl);
  exports["throw"] = $$throw;
  exports["showError"] = showError;
  exports["message"] = $foreign.message;
})(PS);
(function(exports) {
  "use strict";

  exports.unsafeToForeign = function (value) {
    return value;
  };

  exports.unsafeFromForeign = function (value) {
    return value;
  };

  exports.tagOf = function (value) {
    return Object.prototype.toString.call(value).slice(8, -1);
  };
})(PS["Foreign"] = PS["Foreign"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Boolean"] = $PS["Data.Boolean"] || {};
  var exports = $PS["Data.Boolean"];
  var otherwise = true;
  exports["otherwise"] = otherwise;
})(PS);
(function(exports) {
  "use strict";

  exports.fromNumberImpl = function (just) {
    return function (nothing) {
      return function (n) {
        /* jshint bitwise: false */
        return (n | 0) === n ? just(n) : nothing;
      };
    };
  };

  exports.fromStringAsImpl = function (just) {
    return function (nothing) {
      return function (radix) {
        var digits;
        if (radix < 11) {
          digits = "[0-" + (radix - 1).toString() + "]";
        } else if (radix === 11) {
          digits = "[0-9a]";
        } else {
          digits = "[0-9a-" + String.fromCharCode(86 + radix) + "]";
        }
        var pattern = new RegExp("^[\\+\\-]?" + digits + "+$", "i");

        return function (s) {
          /* jshint bitwise: false */
          if (pattern.test(s)) {
            var i = parseInt(s, radix);
            return (i | 0) === i ? just(i) : nothing;
          } else {
            return nothing;
          }
        };
      };
    };
  };
})(PS["Data.Int"] = PS["Data.Int"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Int"] = $PS["Data.Int"] || {};
  var exports = $PS["Data.Int"];
  var $foreign = $PS["Data.Int"];
  var Data_Maybe = $PS["Data.Maybe"];
  var fromStringAs = $foreign.fromStringAsImpl(Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  var fromString = fromStringAs(10);
  var fromNumber = $foreign.fromNumberImpl(Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  exports["fromNumber"] = fromNumber;
  exports["fromString"] = fromString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Foreign"] = $PS["Foreign"] || {};
  var exports = $PS["Foreign"];
  var $foreign = $PS["Foreign"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Control_Monad_Except = $PS["Control.Monad.Except"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Boolean = $PS["Data.Boolean"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Int = $PS["Data.Int"];
  var Data_List_NonEmpty = $PS["Data.List.NonEmpty"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];                                        
  var ForeignError = (function () {
      function ForeignError(value0) {
          this.value0 = value0;
      };
      ForeignError.create = function (value0) {
          return new ForeignError(value0);
      };
      return ForeignError;
  })();
  var TypeMismatch = (function () {
      function TypeMismatch(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      TypeMismatch.create = function (value0) {
          return function (value1) {
              return new TypeMismatch(value0, value1);
          };
      };
      return TypeMismatch;
  })();
  var ErrorAtIndex = (function () {
      function ErrorAtIndex(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ErrorAtIndex.create = function (value0) {
          return function (value1) {
              return new ErrorAtIndex(value0, value1);
          };
      };
      return ErrorAtIndex;
  })();
  var ErrorAtProperty = (function () {
      function ErrorAtProperty(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ErrorAtProperty.create = function (value0) {
          return function (value1) {
              return new ErrorAtProperty(value0, value1);
          };
      };
      return ErrorAtProperty;
  })();
  var showForeignError = new Data_Show.Show(function (v) {
      if (v instanceof ForeignError) {
          return "(ForeignError " + (Data_Show.show(Data_Show.showString)(v.value0) + ")");
      };
      if (v instanceof ErrorAtIndex) {
          return "(ErrorAtIndex " + (Data_Show.show(Data_Show.showInt)(v.value0) + (" " + (Data_Show.show(showForeignError)(v.value1) + ")")));
      };
      if (v instanceof ErrorAtProperty) {
          return "(ErrorAtProperty " + (Data_Show.show(Data_Show.showString)(v.value0) + (" " + (Data_Show.show(showForeignError)(v.value1) + ")")));
      };
      if (v instanceof TypeMismatch) {
          return "(TypeMismatch " + (Data_Show.show(Data_Show.showString)(v.value0) + (" " + (Data_Show.show(Data_Show.showString)(v.value1) + ")")));
      };
      throw new Error("Failed pattern match at Foreign (line 63, column 1 - line 67, column 89): " + [ v.constructor.name ]);
  });
  var renderForeignError = function (v) {
      if (v instanceof ForeignError) {
          return v.value0;
      };
      if (v instanceof ErrorAtIndex) {
          return "Error at array index " + (Data_Show.show(Data_Show.showInt)(v.value0) + (": " + renderForeignError(v.value1)));
      };
      if (v instanceof ErrorAtProperty) {
          return "Error at property " + (Data_Show.show(Data_Show.showString)(v.value0) + (": " + renderForeignError(v.value1)));
      };
      if (v instanceof TypeMismatch) {
          return "Type mismatch: expected " + (v.value0 + (", found " + v.value1));
      };
      throw new Error("Failed pattern match at Foreign (line 72, column 1 - line 72, column 45): " + [ v.constructor.name ]);
  };
  var fail = (function () {
      var $107 = Control_Monad_Error_Class.throwError(Control_Monad_Except_Trans.monadThrowExceptT(Data_Identity.monadIdentity));
      return function ($108) {
          return $107(Data_List_NonEmpty.singleton($108));
      };
  })();
  var unsafeReadTagged = function (tag) {
      return function (value) {
          if ($foreign.tagOf(value) === tag) {
              return Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Data_Identity.monadIdentity))($foreign.unsafeFromForeign(value));
          };
          if (Data_Boolean.otherwise) {
              return fail(new TypeMismatch(tag, $foreign.tagOf(value)));
          };
          throw new Error("Failed pattern match at Foreign (line 106, column 1 - line 106, column 55): " + [ tag.constructor.name, value.constructor.name ]);
      };
  };                                            
  var readNumber = unsafeReadTagged("Number");
  var readInt = function (value) {
      var error = Data_Either.Left.create(Data_List_NonEmpty.singleton(new TypeMismatch("Int", $foreign.tagOf(value))));
      var fromNumber = (function () {
          var $109 = Data_Maybe.maybe(error)(Control_Applicative.pure(Data_Either.applicativeEither));
          return function ($110) {
              return $109(Data_Int.fromNumber($110));
          };
      })();
      return Control_Monad_Except.mapExcept(Data_Either.either(Data_Function["const"](error))(fromNumber))(readNumber(value));
  };
  exports["ForeignError"] = ForeignError;
  exports["renderForeignError"] = renderForeignError;
  exports["unsafeReadTagged"] = unsafeReadTagged;
  exports["readInt"] = readInt;
  exports["fail"] = fail;
  exports["showForeignError"] = showForeignError;
  exports["unsafeToForeign"] = $foreign.unsafeToForeign;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Affjax"] = $PS["Affjax"] || {};
  var exports = $PS["Affjax"];
  var $foreign = $PS["Affjax"];
  var Affjax_RequestBody = $PS["Affjax.RequestBody"];
  var Affjax_RequestHeader = $PS["Affjax.RequestHeader"];
  var Affjax_ResponseFormat = $PS["Affjax.ResponseFormat"];
  var Affjax_ResponseHeader = $PS["Affjax.ResponseHeader"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Control_Monad_Except = $PS["Control.Monad.Except"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Argonaut_Core = $PS["Data.Argonaut.Core"];
  var Data_Argonaut_Parser = $PS["Data.Argonaut.Parser"];
  var Data_Array = $PS["Data.Array"];
  var Data_Either = $PS["Data.Either"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_FormURLEncoded = $PS["Data.FormURLEncoded"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_HTTP_Method = $PS["Data.HTTP.Method"];
  var Data_HeytingAlgebra = $PS["Data.HeytingAlgebra"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_List_NonEmpty = $PS["Data.List.NonEmpty"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Nullable = $PS["Data.Nullable"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Compat = $PS["Effect.Aff.Compat"];
  var Effect_Exception = $PS["Effect.Exception"];
  var Foreign = $PS["Foreign"];                
  var RequestContentError = (function () {
      function RequestContentError(value0) {
          this.value0 = value0;
      };
      RequestContentError.create = function (value0) {
          return new RequestContentError(value0);
      };
      return RequestContentError;
  })();
  var ResponseBodyError = (function () {
      function ResponseBodyError(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ResponseBodyError.create = function (value0) {
          return function (value1) {
              return new ResponseBodyError(value0, value1);
          };
      };
      return ResponseBodyError;
  })();
  var XHRError = (function () {
      function XHRError(value0) {
          this.value0 = value0;
      };
      XHRError.create = function (value0) {
          return new XHRError(value0);
      };
      return XHRError;
  })();
  var request = function (req) {
      var parseJSON = function (v) {
          if (v === "") {
              return Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Data_Identity.monadIdentity))(Data_Argonaut_Core.jsonEmptyObject);
          };
          return Data_Either.either(function ($47) {
              return Foreign.fail(Foreign.ForeignError.create($47));
          })(Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Data_Identity.monadIdentity)))(Data_Argonaut_Parser.jsonParser(v));
      };
      var fromResponse = (function () {
          if (req.responseFormat instanceof Affjax_ResponseFormat["ArrayBuffer"]) {
              return Foreign.unsafeReadTagged("ArrayBuffer");
          };
          if (req.responseFormat instanceof Affjax_ResponseFormat.Blob) {
              return Foreign.unsafeReadTagged("Blob");
          };
          if (req.responseFormat instanceof Affjax_ResponseFormat.Document) {
              return Foreign.unsafeReadTagged("Document");
          };
          if (req.responseFormat instanceof Affjax_ResponseFormat.Json) {
              return Control_Bind.composeKleisliFlipped(Control_Monad_Except_Trans.bindExceptT(Data_Identity.monadIdentity))(function ($48) {
                  return req.responseFormat.value0(parseJSON($48));
              })(Foreign.unsafeReadTagged("String"));
          };
          if (req.responseFormat instanceof Affjax_ResponseFormat["String"]) {
              return Foreign.unsafeReadTagged("String");
          };
          if (req.responseFormat instanceof Affjax_ResponseFormat.Ignore) {
              return Data_Function["const"](req.responseFormat.value0(Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Data_Identity.monadIdentity))(Data_Unit.unit)));
          };
          throw new Error("Failed pattern match at Affjax (line 237, column 18 - line 243, column 57): " + [ req.responseFormat.constructor.name ]);
      })();
      var extractContent = function (v) {
          if (v instanceof Affjax_RequestBody.ArrayView) {
              return Data_Either.Right.create(v.value0(Foreign.unsafeToForeign));
          };
          if (v instanceof Affjax_RequestBody.Blob) {
              return Data_Either.Right.create(Foreign.unsafeToForeign(v.value0));
          };
          if (v instanceof Affjax_RequestBody.Document) {
              return Data_Either.Right.create(Foreign.unsafeToForeign(v.value0));
          };
          if (v instanceof Affjax_RequestBody["String"]) {
              return Data_Either.Right.create(Foreign.unsafeToForeign(v.value0));
          };
          if (v instanceof Affjax_RequestBody.FormData) {
              return Data_Either.Right.create(Foreign.unsafeToForeign(v.value0));
          };
          if (v instanceof Affjax_RequestBody.FormURLEncoded) {
              return Data_Either.note("Body contains values that cannot be encoded as application/x-www-form-urlencoded")(Data_Functor.map(Data_Maybe.functorMaybe)(Foreign.unsafeToForeign)(Data_FormURLEncoded.encode(v.value0)));
          };
          if (v instanceof Affjax_RequestBody.Json) {
              return Data_Either.Right.create(Foreign.unsafeToForeign(Data_Argonaut_Core.stringify(v.value0)));
          };
          throw new Error("Failed pattern match at Affjax (line 203, column 20 - line 218, column 69): " + [ v.constructor.name ]);
      };
      var addHeader = function (mh) {
          return function (hs) {
              if (mh instanceof Data_Maybe.Just && !Data_Foldable.any(Data_Foldable.foldableArray)(Data_HeytingAlgebra.heytingAlgebraBoolean)(Data_Function.on(Data_Eq.eq(Data_Eq.eqString))(Affjax_RequestHeader.name)(mh.value0))(hs)) {
                  return Data_Array.snoc(hs)(mh.value0);
              };
              return hs;
          };
      };
      var headers = function (reqContent) {
          return addHeader(Data_Functor.map(Data_Maybe.functorMaybe)(Affjax_RequestHeader.ContentType.create)(Control_Bind.bindFlipped(Data_Maybe.bindMaybe)(Affjax_RequestBody.toMediaType)(reqContent)))(addHeader(Data_Functor.map(Data_Maybe.functorMaybe)(Affjax_RequestHeader.Accept.create)(Affjax_ResponseFormat.toMediaType(req.responseFormat)))(req.headers));
      };
      var ajaxRequest = function (v) {
          return {
              method: Data_HTTP_Method.print(req.method),
              url: req.url,
              headers: Data_Functor.map(Data_Functor.functorArray)(function (h) {
                  return {
                      field: Affjax_RequestHeader.name(h),
                      value: Affjax_RequestHeader.value(h)
                  };
              })(headers(req.content)),
              content: v,
              responseType: Affjax_ResponseFormat.toResponseType(req.responseFormat),
              username: Data_Nullable.toNullable(req.username),
              password: Data_Nullable.toNullable(req.password),
              withCredentials: req.withCredentials
          };
      };
      var send = function (content) {
          return Data_Functor.mapFlipped(Effect_Aff.functorAff)(Control_Monad_Error_Class["try"](Effect_Aff.monadErrorAff)(Effect_Aff_Compat.fromEffectFnAff($foreign["_ajax"](Affjax_ResponseHeader.ResponseHeader.create, ajaxRequest(content)))))(function (v) {
              if (v instanceof Data_Either.Right) {
                  var v1 = Control_Monad_Except.runExcept(fromResponse(v.value0.body));
                  if (v1 instanceof Data_Either.Left) {
                      return new Data_Either.Left(new ResponseBodyError(Data_List_NonEmpty.head(v1.value0), v.value0));
                  };
                  if (v1 instanceof Data_Either.Right) {
                      return new Data_Either.Right({
                          body: v1.value0,
                          headers: v.value0.headers,
                          status: v.value0.status,
                          statusText: v.value0.statusText
                      });
                  };
                  throw new Error("Failed pattern match at Affjax (line 184, column 9 - line 186, column 52): " + [ v1.constructor.name ]);
              };
              if (v instanceof Data_Either.Left) {
                  return new Data_Either.Left(new XHRError(v.value0));
              };
              throw new Error("Failed pattern match at Affjax (line 182, column 86 - line 188, column 28): " + [ v.constructor.name ]);
          });
      };
      if (req.content instanceof Data_Maybe.Nothing) {
          return send(Data_Nullable.toNullable(Data_Maybe.Nothing.value));
      };
      if (req.content instanceof Data_Maybe.Just) {
          var v = extractContent(req.content.value0);
          if (v instanceof Data_Either.Right) {
              return send(Data_Nullable.toNullable(new Data_Maybe.Just(v.value0)));
          };
          if (v instanceof Data_Either.Left) {
              return Control_Applicative.pure(Effect_Aff.applicativeAff)(new Data_Either.Left(new RequestContentError(v.value0)));
          };
          throw new Error("Failed pattern match at Affjax (line 173, column 7 - line 177, column 48): " + [ v.constructor.name ]);
      };
      throw new Error("Failed pattern match at Affjax (line 169, column 3 - line 177, column 48): " + [ req.content.constructor.name ]);
  };
  var printError = function (v) {
      if (v instanceof RequestContentError) {
          return "There was a problem with the request content: " + v.value0;
      };
      if (v instanceof ResponseBodyError) {
          return "There was a problem with the response body: " + Foreign.renderForeignError(v.value0);
      };
      if (v instanceof XHRError) {
          return "There was a problem making the request: " + Effect_Exception.message(v.value0);
      };
      throw new Error("Failed pattern match at Affjax (line 91, column 14 - line 97, column 66): " + [ v.constructor.name ]);
  };
  var defaultRequest = {
      method: new Data_Either.Left(Data_HTTP_Method.GET.value),
      url: "/",
      headers: [  ],
      content: Data_Maybe.Nothing.value,
      username: Data_Maybe.Nothing.value,
      password: Data_Maybe.Nothing.value,
      withCredentials: false,
      responseFormat: Affjax_ResponseFormat.ignore
  };
  exports["defaultRequest"] = defaultRequest;
  exports["printError"] = printError;
  exports["request"] = request;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Chalk"] = $PS["Chalk"] || {};
  var exports = $PS["Chalk"];
  var Data_Show = $PS["Data.Show"];                
  var text = function (start) {
      return function (end) {
          return function (source) {
              return "\x1b[" + (Data_Show.show(Data_Show.showInt)(start) + ("m" + (source + ("\x1b[" + (Data_Show.show(Data_Show.showInt)(end) + "m")))));
          };
      };
  };                          
  var white = text(37)(39);      
  var yellow = text(33)(39);   
  var red = text(31)(39);        
  var green = text(32)(39);
  var gray = text(90)(39);
  exports["red"] = red;
  exports["green"] = green;
  exports["yellow"] = yellow;
  exports["white"] = white;
  exports["gray"] = gray;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Alternative"] = $PS["Control.Alternative"] || {};
  var exports = $PS["Control.Alternative"];              
  var Alternative = function (Applicative0, Plus1) {
      this.Applicative0 = Applicative0;
      this.Plus1 = Plus1;
  };
  exports["Alternative"] = Alternative;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Extend"] = $PS["Control.Extend"] || {};
  var exports = $PS["Control.Extend"];                       
  var Extend = function (Functor0, extend) {
      this.Functor0 = Functor0;
      this.extend = extend;
  };                       
  var extend = function (dict) {
      return dict.extend;
  };
  exports["Extend"] = Extend;
  exports["extend"] = extend;
})(PS);
(function(exports) {
  "use strict";

  exports.defer = function (thunk) {
    var v = null;
    return function() {
      if (thunk === undefined) return v;

      v = thunk();
      thunk = undefined; // eslint-disable-line no-param-reassign
      return v;
    };
  };

  exports.force = function (l) {
    return l();
  };
})(PS["Data.Lazy"] = PS["Data.Lazy"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Lazy"] = $PS["Data.Lazy"] || {};
  var exports = $PS["Data.Lazy"];
  var $foreign = $PS["Data.Lazy"];
  var Data_Functor = $PS["Data.Functor"];
  var functorLazy = new Data_Functor.Functor(function (f) {
      return function (l) {
          return $foreign.defer(function (v) {
              return f($foreign.force(l));
          });
      };
  });
  exports["functorLazy"] = functorLazy;
  exports["defer"] = $foreign.defer;
  exports["force"] = $foreign.force;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Comonad.Cofree"] = $PS["Control.Comonad.Cofree"] || {};
  var exports = $PS["Control.Comonad.Cofree"];
  var Control_Extend = $PS["Control.Extend"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Lazy = $PS["Data.Lazy"];
  var Data_Tuple = $PS["Data.Tuple"];
  var tail = function (v) {
      return Data_Tuple.snd(Data_Lazy.force(v));
  };
  var mkCofree = function (a) {
      return function (t) {
          return Data_Lazy.defer(function (v) {
              return new Data_Tuple.Tuple(a, t);
          });
      };
  };
  var head = function (v) {
      return Data_Tuple.fst(Data_Lazy.force(v));
  };
  var functorCofree = function (dictFunctor) {
      return new Data_Functor.Functor(function (f) {
          var loop = function (v) {
              return Data_Functor.map(Data_Lazy.functorLazy)(function (v1) {
                  return new Data_Tuple.Tuple(f(v1.value0), Data_Functor.map(dictFunctor)(loop)(v1.value1));
              })(v);
          };
          return loop;
      });
  };
  var extendCofree = function (dictFunctor) {
      return new Control_Extend.Extend(function () {
          return functorCofree(dictFunctor);
      }, function (f) {
          var loop = function (v) {
              return Data_Functor.map(Data_Lazy.functorLazy)(function (v1) {
                  return new Data_Tuple.Tuple(f(v), Data_Functor.map(dictFunctor)(loop)(v1.value1));
              })(v);
          };
          return loop;
      });
  };
  exports["mkCofree"] = mkCofree;
  exports["head"] = head;
  exports["tail"] = tail;
  exports["extendCofree"] = extendCofree;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Rec.Class"] = $PS["Control.Monad.Rec.Class"] || {};
  var exports = $PS["Control.Monad.Rec.Class"];
  var Data_Identity = $PS["Data.Identity"];          
  var Loop = (function () {
      function Loop(value0) {
          this.value0 = value0;
      };
      Loop.create = function (value0) {
          return new Loop(value0);
      };
      return Loop;
  })();
  var Done = (function () {
      function Done(value0) {
          this.value0 = value0;
      };
      Done.create = function (value0) {
          return new Done(value0);
      };
      return Done;
  })();
  var MonadRec = function (Monad0, tailRecM) {
      this.Monad0 = Monad0;
      this.tailRecM = tailRecM;
  };
  var tailRecM = function (dict) {
      return dict.tailRecM;
  };
  var tailRec = function (f) {
      var go = function ($copy_v) {
          var $tco_done = false;
          var $tco_result;
          function $tco_loop(v) {
              if (v instanceof Loop) {
                  $copy_v = f(v.value0);
                  return;
              };
              if (v instanceof Done) {
                  $tco_done = true;
                  return v.value0;
              };
              throw new Error("Failed pattern match at Control.Monad.Rec.Class (line 93, column 3 - line 93, column 25): " + [ v.constructor.name ]);
          };
          while (!$tco_done) {
              $tco_result = $tco_loop($copy_v);
          };
          return $tco_result;
      };
      return function ($58) {
          return go(f($58));
      };
  }; 
  var monadRecIdentity = new MonadRec(function () {
      return Data_Identity.monadIdentity;
  }, function (f) {
      var runIdentity = function (v) {
          return v;
      };
      var $59 = tailRec(function ($61) {
          return runIdentity(f($61));
      });
      return function ($60) {
          return Data_Identity.Identity($59($60));
      };
  });
  exports["Loop"] = Loop;
  exports["Done"] = Done;
  exports["MonadRec"] = MonadRec;
  exports["tailRecM"] = tailRecM;
  exports["monadRecIdentity"] = monadRecIdentity;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.List"] = $PS["Data.List"] || {};
  var exports = $PS["Data.List"];
  var Control_Category = $PS["Control.Category"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unfoldable = $PS["Data.Unfoldable"];                                  
  var uncons = function (v) {
      if (v instanceof Data_List_Types.Nil) {
          return Data_Maybe.Nothing.value;
      };
      if (v instanceof Data_List_Types.Cons) {
          return new Data_Maybe.Just({
              head: v.value0,
              tail: v.value1
          });
      };
      throw new Error("Failed pattern match at Data.List (line 259, column 1 - line 259, column 66): " + [ v.constructor.name ]);
  };
  var toUnfoldable = function (dictUnfoldable) {
      return Data_Unfoldable.unfoldr(dictUnfoldable)(function (xs) {
          return Data_Functor.map(Data_Maybe.functorMaybe)(function (rec) {
              return new Data_Tuple.Tuple(rec.head, rec.tail);
          })(uncons(xs));
      });
  };
  var tail = function (v) {
      if (v instanceof Data_List_Types.Nil) {
          return Data_Maybe.Nothing.value;
      };
      if (v instanceof Data_List_Types.Cons) {
          return new Data_Maybe.Just(v.value1);
      };
      throw new Error("Failed pattern match at Data.List (line 245, column 1 - line 245, column 43): " + [ v.constructor.name ]);
  };
  var reverse = (function () {
      var go = function ($copy_acc) {
          return function ($copy_v) {
              var $tco_var_acc = $copy_acc;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(acc, v) {
                  if (v instanceof Data_List_Types.Nil) {
                      $tco_done = true;
                      return acc;
                  };
                  if (v instanceof Data_List_Types.Cons) {
                      $tco_var_acc = new Data_List_Types.Cons(v.value0, acc);
                      $copy_v = v.value1;
                      return;
                  };
                  throw new Error("Failed pattern match at Data.List (line 368, column 3 - line 368, column 19): " + [ acc.constructor.name, v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_acc, $copy_v);
              };
              return $tco_result;
          };
      };
      return go(Data_List_Types.Nil.value);
  })();                                                                                       
  var mapMaybe = function (f) {
      var go = function ($copy_acc) {
          return function ($copy_v) {
              var $tco_var_acc = $copy_acc;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(acc, v) {
                  if (v instanceof Data_List_Types.Nil) {
                      $tco_done = true;
                      return reverse(acc);
                  };
                  if (v instanceof Data_List_Types.Cons) {
                      var v1 = f(v.value0);
                      if (v1 instanceof Data_Maybe.Nothing) {
                          $tco_var_acc = acc;
                          $copy_v = v.value1;
                          return;
                      };
                      if (v1 instanceof Data_Maybe.Just) {
                          $tco_var_acc = new Data_List_Types.Cons(v1.value0, acc);
                          $copy_v = v.value1;
                          return;
                      };
                      throw new Error("Failed pattern match at Data.List (line 419, column 5 - line 421, column 32): " + [ v1.constructor.name ]);
                  };
                  throw new Error("Failed pattern match at Data.List (line 417, column 3 - line 417, column 27): " + [ acc.constructor.name, v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_acc, $copy_v);
              };
              return $tco_result;
          };
      };
      return go(Data_List_Types.Nil.value);
  };
  var head = function (v) {
      if (v instanceof Data_List_Types.Nil) {
          return Data_Maybe.Nothing.value;
      };
      if (v instanceof Data_List_Types.Cons) {
          return new Data_Maybe.Just(v.value0);
      };
      throw new Error("Failed pattern match at Data.List (line 230, column 1 - line 230, column 22): " + [ v.constructor.name ]);
  };
  var fromFoldable = function (dictFoldable) {
      return Data_Foldable.foldr(dictFoldable)(Data_List_Types.Cons.create)(Data_List_Types.Nil.value);
  };
  var catMaybes = mapMaybe(Control_Category.identity(Control_Category.categoryFn));
  exports["toUnfoldable"] = toUnfoldable;
  exports["fromFoldable"] = fromFoldable;
  exports["head"] = head;
  exports["tail"] = tail;
  exports["reverse"] = reverse;
  exports["catMaybes"] = catMaybes;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.CatQueue"] = $PS["Data.CatQueue"] || {};
  var exports = $PS["Data.CatQueue"];
  var Data_List = $PS["Data.List"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Tuple = $PS["Data.Tuple"];                            
  var CatQueue = (function () {
      function CatQueue(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      CatQueue.create = function (value0) {
          return function (value1) {
              return new CatQueue(value0, value1);
          };
      };
      return CatQueue;
  })();
  var uncons = function ($copy_v) {
      var $tco_done = false;
      var $tco_result;
      function $tco_loop(v) {
          if (v.value0 instanceof Data_List_Types.Nil && v.value1 instanceof Data_List_Types.Nil) {
              $tco_done = true;
              return Data_Maybe.Nothing.value;
          };
          if (v.value0 instanceof Data_List_Types.Nil) {
              $copy_v = new CatQueue(Data_List.reverse(v.value1), Data_List_Types.Nil.value);
              return;
          };
          if (v.value0 instanceof Data_List_Types.Cons) {
              $tco_done = true;
              return new Data_Maybe.Just(new Data_Tuple.Tuple(v.value0.value0, new CatQueue(v.value0.value1, v.value1)));
          };
          throw new Error("Failed pattern match at Data.CatQueue (line 83, column 1 - line 83, column 63): " + [ v.constructor.name ]);
      };
      while (!$tco_done) {
          $tco_result = $tco_loop($copy_v);
      };
      return $tco_result;
  };
  var snoc = function (v) {
      return function (a) {
          return new CatQueue(v.value0, new Data_List_Types.Cons(a, v.value1));
      };
  };
  var $$null = function (v) {
      if (v.value0 instanceof Data_List_Types.Nil && v.value1 instanceof Data_List_Types.Nil) {
          return true;
      };
      return false;
  };                                                                                                
  var empty = new CatQueue(Data_List_Types.Nil.value, Data_List_Types.Nil.value);
  exports["empty"] = empty;
  exports["null"] = $$null;
  exports["snoc"] = snoc;
  exports["uncons"] = uncons;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.CatList"] = $PS["Data.CatList"] || {};
  var exports = $PS["Data.CatList"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Data_CatQueue = $PS["Data.CatQueue"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Tuple = $PS["Data.Tuple"];                            
  var CatNil = (function () {
      function CatNil() {

      };
      CatNil.value = new CatNil();
      return CatNil;
  })();
  var CatCons = (function () {
      function CatCons(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      CatCons.create = function (value0) {
          return function (value1) {
              return new CatCons(value0, value1);
          };
      };
      return CatCons;
  })();
  var link = function (v) {
      return function (v1) {
          if (v instanceof CatNil) {
              return v1;
          };
          if (v1 instanceof CatNil) {
              return v;
          };
          if (v instanceof CatCons) {
              return new CatCons(v.value0, Data_CatQueue.snoc(v.value1)(v1));
          };
          throw new Error("Failed pattern match at Data.CatList (line 109, column 1 - line 109, column 54): " + [ v.constructor.name, v1.constructor.name ]);
      };
  };
  var foldr = function (k) {
      return function (b) {
          return function (q) {
              var foldl = function ($copy_v) {
                  return function ($copy_c) {
                      return function ($copy_v1) {
                          var $tco_var_v = $copy_v;
                          var $tco_var_c = $copy_c;
                          var $tco_done = false;
                          var $tco_result;
                          function $tco_loop(v, c, v1) {
                              if (v1 instanceof Data_List_Types.Nil) {
                                  $tco_done = true;
                                  return c;
                              };
                              if (v1 instanceof Data_List_Types.Cons) {
                                  $tco_var_v = v;
                                  $tco_var_c = v(c)(v1.value0);
                                  $copy_v1 = v1.value1;
                                  return;
                              };
                              throw new Error("Failed pattern match at Data.CatList (line 125, column 3 - line 125, column 59): " + [ v.constructor.name, c.constructor.name, v1.constructor.name ]);
                          };
                          while (!$tco_done) {
                              $tco_result = $tco_loop($tco_var_v, $tco_var_c, $copy_v1);
                          };
                          return $tco_result;
                      };
                  };
              };
              var go = function ($copy_xs) {
                  return function ($copy_ys) {
                      var $tco_var_xs = $copy_xs;
                      var $tco_done = false;
                      var $tco_result;
                      function $tco_loop(xs, ys) {
                          var v = Data_CatQueue.uncons(xs);
                          if (v instanceof Data_Maybe.Nothing) {
                              $tco_done = true;
                              return foldl(function (x) {
                                  return function (i) {
                                      return i(x);
                                  };
                              })(b)(ys);
                          };
                          if (v instanceof Data_Maybe.Just) {
                              $tco_var_xs = v.value0.value1;
                              $copy_ys = new Data_List_Types.Cons(k(v.value0.value0), ys);
                              return;
                          };
                          throw new Error("Failed pattern match at Data.CatList (line 121, column 14 - line 123, column 67): " + [ v.constructor.name ]);
                      };
                      while (!$tco_done) {
                          $tco_result = $tco_loop($tco_var_xs, $copy_ys);
                      };
                      return $tco_result;
                  };
              };
              return go(q)(Data_List_Types.Nil.value);
          };
      };
  };
  var uncons = function (v) {
      if (v instanceof CatNil) {
          return Data_Maybe.Nothing.value;
      };
      if (v instanceof CatCons) {
          return new Data_Maybe.Just(new Data_Tuple.Tuple(v.value0, (function () {
              var $44 = Data_CatQueue["null"](v.value1);
              if ($44) {
                  return CatNil.value;
              };
              return foldr(link)(CatNil.value)(v.value1);
          })()));
      };
      throw new Error("Failed pattern match at Data.CatList (line 100, column 1 - line 100, column 61): " + [ v.constructor.name ]);
  };
  var foldableCatList = new Data_Foldable.Foldable(function (dictMonoid) {
      return Data_Foldable.foldMapDefaultL(foldableCatList)(dictMonoid);
  }, function (f) {
      var go = function ($copy_acc) {
          return function ($copy_q) {
              var $tco_var_acc = $copy_acc;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(acc, q) {
                  var v = uncons(q);
                  if (v instanceof Data_Maybe.Just) {
                      $tco_var_acc = f(acc)(v.value0.value0);
                      $copy_q = v.value0.value1;
                      return;
                  };
                  if (v instanceof Data_Maybe.Nothing) {
                      $tco_done = true;
                      return acc;
                  };
                  throw new Error("Failed pattern match at Data.CatList (line 157, column 16 - line 159, column 22): " + [ v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_acc, $copy_q);
              };
              return $tco_result;
          };
      };
      return go;
  }, function (f) {
      return function (s) {
          return function (l) {
              return Data_Foldable.foldrDefault(foldableCatList)(f)(s)(l);
          };
      };
  });                                                                           
  var foldMap = function (dictMonoid) {
      return function (f) {
          return function (v) {
              if (v instanceof CatNil) {
                  return Data_Monoid.mempty(dictMonoid);
              };
              if (v instanceof CatCons) {
                  var d = (function () {
                      var $53 = Data_CatQueue["null"](v.value1);
                      if ($53) {
                          return CatNil.value;
                      };
                      return foldr(link)(CatNil.value)(v.value1);
                  })();
                  return Data_Semigroup.append(dictMonoid.Semigroup0())(f(v.value0))(foldMap(dictMonoid)(f)(d));
              };
              throw new Error("Failed pattern match at Data.CatList (line 135, column 1 - line 135, column 62): " + [ f.constructor.name, v.constructor.name ]);
          };
      };
  };
  var empty = CatNil.value;
  var append = link;
  var cons = function (a) {
      return function (cat) {
          return append(new CatCons(a, Data_CatQueue.empty))(cat);
      };
  };
  var functorCatList = new Data_Functor.Functor(function (v) {
      return function (v1) {
          if (v1 instanceof CatNil) {
              return CatNil.value;
          };
          if (v1 instanceof CatCons) {
              var d = (function () {
                  var $58 = Data_CatQueue["null"](v1.value1);
                  if ($58) {
                      return CatNil.value;
                  };
                  return foldr(link)(CatNil.value)(v1.value1);
              })();
              return cons(v(v1.value0))(Data_Functor.map(functorCatList)(v)(d));
          };
          throw new Error("Failed pattern match at Data.CatList (line 185, column 1 - line 189, column 26): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var singleton = function (a) {
      return cons(a)(CatNil.value);
  }; 
  var semigroupCatList = new Data_Semigroup.Semigroup(append);
  var monoidCatList = new Data_Monoid.Monoid(function () {
      return semigroupCatList;
  }, CatNil.value);
  var monadCatList = new Control_Monad.Monad(function () {
      return applicativeCatList;
  }, function () {
      return bindCatList;
  });
  var bindCatList = new Control_Bind.Bind(function () {
      return applyCatList;
  }, Data_Function.flip(foldMap(monoidCatList)));
  var applyCatList = new Control_Apply.Apply(function () {
      return functorCatList;
  }, Control_Monad.ap(monadCatList));
  var applicativeCatList = new Control_Applicative.Applicative(function () {
      return applyCatList;
  }, singleton);
  var snoc = function (cat) {
      return function (a) {
          return append(cat)(new CatCons(a, Data_CatQueue.empty));
      };
  };
  exports["empty"] = empty;
  exports["snoc"] = snoc;
  exports["uncons"] = uncons;
  exports["semigroupCatList"] = semigroupCatList;
  exports["monoidCatList"] = monoidCatList;
  exports["foldableCatList"] = foldableCatList;
  exports["functorCatList"] = functorCatList;
  exports["applicativeCatList"] = applicativeCatList;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.Free"] = $PS["Control.Monad.Free"] || {};
  var exports = $PS["Control.Monad.Free"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad = $PS["Control.Monad"];
  var Control_Monad_Rec_Class = $PS["Control.Monad.Rec.Class"];
  var Data_CatList = $PS["Data.CatList"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Free = (function () {
      function Free(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Free.create = function (value0) {
          return function (value1) {
              return new Free(value0, value1);
          };
      };
      return Free;
  })();
  var Return = (function () {
      function Return(value0) {
          this.value0 = value0;
      };
      Return.create = function (value0) {
          return new Return(value0);
      };
      return Return;
  })();
  var Bind = (function () {
      function Bind(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Bind.create = function (value0) {
          return function (value1) {
              return new Bind(value0, value1);
          };
      };
      return Bind;
  })();
  var toView = function ($copy_v) {
      var $tco_done = false;
      var $tco_result;
      function $tco_loop(v) {
          var runExpF = function (v2) {
              return v2;
          };
          var concatF = function (v2) {
              return function (r) {
                  return new Free(v2.value0, Data_Semigroup.append(Data_CatList.semigroupCatList)(v2.value1)(r));
              };
          };
          if (v.value0 instanceof Return) {
              var v2 = Data_CatList.uncons(v.value1);
              if (v2 instanceof Data_Maybe.Nothing) {
                  $tco_done = true;
                  return new Return(v.value0.value0);
              };
              if (v2 instanceof Data_Maybe.Just) {
                  $copy_v = concatF(runExpF(v2.value0.value0)(v.value0.value0))(v2.value0.value1);
                  return;
              };
              throw new Error("Failed pattern match at Control.Monad.Free (line 227, column 7 - line 231, column 64): " + [ v2.constructor.name ]);
          };
          if (v.value0 instanceof Bind) {
              $tco_done = true;
              return new Bind(v.value0.value0, function (a) {
                  return concatF(v.value0.value1(a))(v.value1);
              });
          };
          throw new Error("Failed pattern match at Control.Monad.Free (line 225, column 3 - line 233, column 56): " + [ v.value0.constructor.name ]);
      };
      while (!$tco_done) {
          $tco_result = $tco_loop($copy_v);
      };
      return $tco_result;
  };
  var fromView = function (f) {
      return new Free(f, Data_CatList.empty);
  };
  var freeMonad = new Control_Monad.Monad(function () {
      return freeApplicative;
  }, function () {
      return freeBind;
  });
  var freeFunctor = new Data_Functor.Functor(function (k) {
      return function (f) {
          return Control_Bind.bindFlipped(freeBind)((function () {
              var $120 = Control_Applicative.pure(freeApplicative);
              return function ($121) {
                  return $120(k($121));
              };
          })())(f);
      };
  });
  var freeBind = new Control_Bind.Bind(function () {
      return freeApply;
  }, function (v) {
      return function (k) {
          return new Free(v.value0, Data_CatList.snoc(v.value1)(k));
      };
  });
  var freeApply = new Control_Apply.Apply(function () {
      return freeFunctor;
  }, Control_Monad.ap(freeMonad));
  var freeApplicative = new Control_Applicative.Applicative(function () {
      return freeApply;
  }, function ($122) {
      return fromView(Return.create($122));
  });
  var liftF = function (f) {
      return fromView(new Bind(f, (function () {
          var $123 = Control_Applicative.pure(freeApplicative);
          return function ($124) {
              return $123($124);
          };
      })()));
  };
  var substFree = function (k) {
      var go = function (f) {
          var v = toView(f);
          if (v instanceof Return) {
              return Control_Applicative.pure(freeApplicative)(v.value0);
          };
          if (v instanceof Bind) {
              return Control_Bind.bind(freeBind)(k(v.value0))(Data_Functor.map(Data_Functor.functorFn)(go)(v.value1));
          };
          throw new Error("Failed pattern match at Control.Monad.Free (line 168, column 10 - line 170, column 33): " + [ v.constructor.name ]);
      };
      return go;
  };
  var hoistFree = function (k) {
      return substFree(function ($125) {
          return liftF(k($125));
      });
  };
  var foldFree = function (dictMonadRec) {
      return function (k) {
          var go = function (f) {
              var v = toView(f);
              if (v instanceof Return) {
                  return Data_Functor.map((((dictMonadRec.Monad0()).Bind1()).Apply0()).Functor0())(Control_Monad_Rec_Class.Done.create)(Control_Applicative.pure((dictMonadRec.Monad0()).Applicative0())(v.value0));
              };
              if (v instanceof Bind) {
                  return Data_Functor.map((((dictMonadRec.Monad0()).Bind1()).Apply0()).Functor0())(function ($136) {
                      return Control_Monad_Rec_Class.Loop.create(v.value1($136));
                  })(k(v.value0));
              };
              throw new Error("Failed pattern match at Control.Monad.Free (line 158, column 10 - line 160, column 37): " + [ v.constructor.name ]);
          };
          return Control_Monad_Rec_Class.tailRecM(dictMonadRec)(go);
      };
  };
  exports["liftF"] = liftF;
  exports["hoistFree"] = hoistFree;
  exports["foldFree"] = foldFree;
  exports["freeBind"] = freeBind;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.State"] = $PS["Control.Monad.State"] || {};
  var exports = $PS["Control.Monad.State"];
  var execState = function (v) {
      return function (s) {
          var v1 = v(s);
          return v1.value1;
      };
  };
  var evalState = function (v) {
      return function (s) {
          var v1 = v(s);
          return v1.value0;
      };
  };
  exports["evalState"] = evalState;
  exports["execState"] = execState;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Control.Monad.State.Trans"] = $PS["Control.Monad.State.Trans"] || {};
  var exports = $PS["Control.Monad.State.Trans"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Lazy = $PS["Control.Lazy"];
  var Control_Monad = $PS["Control.Monad"];
  var Control_Monad_Rec_Class = $PS["Control.Monad.Rec.Class"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unit = $PS["Data.Unit"];                      
  var StateT = function (x) {
      return x;
  };
  var runStateT = function (v) {
      return v;
  };
  var lazyStateT = new Control_Lazy.Lazy(function (f) {
      return function (s) {
          var v = f(Data_Unit.unit);
          return v(s);
      };
  });
  var functorStateT = function (dictFunctor) {
      return new Data_Functor.Functor(function (f) {
          return function (v) {
              return function (s) {
                  return Data_Functor.map(dictFunctor)(function (v1) {
                      return new Data_Tuple.Tuple(f(v1.value0), v1.value1);
                  })(v(s));
              };
          };
      });
  };
  var evalStateT = function (dictFunctor) {
      return function (v) {
          return function (s) {
              return Data_Functor.map(dictFunctor)(Data_Tuple.fst)(v(s));
          };
      };
  };
  var monadStateT = function (dictMonad) {
      return new Control_Monad.Monad(function () {
          return applicativeStateT(dictMonad);
      }, function () {
          return bindStateT(dictMonad);
      });
  };
  var bindStateT = function (dictMonad) {
      return new Control_Bind.Bind(function () {
          return applyStateT(dictMonad);
      }, function (v) {
          return function (f) {
              return function (s) {
                  return Control_Bind.bind(dictMonad.Bind1())(v(s))(function (v1) {
                      var v3 = f(v1.value0);
                      return v3(v1.value1);
                  });
              };
          };
      });
  };
  var applyStateT = function (dictMonad) {
      return new Control_Apply.Apply(function () {
          return functorStateT(((dictMonad.Bind1()).Apply0()).Functor0());
      }, Control_Monad.ap(monadStateT(dictMonad)));
  };
  var applicativeStateT = function (dictMonad) {
      return new Control_Applicative.Applicative(function () {
          return applyStateT(dictMonad);
      }, function (a) {
          return function (s) {
              return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(a, s));
          };
      });
  };
  var monadRecStateT = function (dictMonadRec) {
      return new Control_Monad_Rec_Class.MonadRec(function () {
          return monadStateT(dictMonadRec.Monad0());
      }, function (f) {
          return function (a) {
              var f$prime = function (v) {
                  var v1 = f(v.value0);
                  return Control_Bind.bind((dictMonadRec.Monad0()).Bind1())(v1(v.value1))(function (v2) {
                      return Control_Applicative.pure((dictMonadRec.Monad0()).Applicative0())((function () {
                          if (v2.value0 instanceof Control_Monad_Rec_Class.Loop) {
                              return new Control_Monad_Rec_Class.Loop(new Data_Tuple.Tuple(v2.value0.value0, v2.value1));
                          };
                          if (v2.value0 instanceof Control_Monad_Rec_Class.Done) {
                              return new Control_Monad_Rec_Class.Done(new Data_Tuple.Tuple(v2.value0.value0, v2.value1));
                          };
                          throw new Error("Failed pattern match at Control.Monad.State.Trans (line 87, column 16 - line 89, column 40): " + [ v2.value0.constructor.name ]);
                      })());
                  });
              };
              return function (s) {
                  return Control_Monad_Rec_Class.tailRecM(dictMonadRec)(f$prime)(new Data_Tuple.Tuple(a, s));
              };
          };
      });
  };
  var monadStateStateT = function (dictMonad) {
      return new Control_Monad_State_Class.MonadState(function () {
          return monadStateT(dictMonad);
      }, function (f) {
          return StateT((function () {
              var $112 = Control_Applicative.pure(dictMonad.Applicative0());
              return function ($113) {
                  return $112(f($113));
              };
          })());
      });
  };
  exports["StateT"] = StateT;
  exports["runStateT"] = runStateT;
  exports["evalStateT"] = evalStateT;
  exports["functorStateT"] = functorStateT;
  exports["applicativeStateT"] = applicativeStateT;
  exports["bindStateT"] = bindStateT;
  exports["monadStateT"] = monadStateT;
  exports["monadRecStateT"] = monadRecStateT;
  exports["lazyStateT"] = lazyStateT;
  exports["monadStateStateT"] = monadStateStateT;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Argonaut.Decode.Error"] = $PS["Data.Argonaut.Decode.Error"] || {};
  var exports = $PS["Data.Argonaut.Decode.Error"];
  var Data_Argonaut_Core = $PS["Data.Argonaut.Core"];
  var Data_Show = $PS["Data.Show"];                
  var TypeMismatch = (function () {
      function TypeMismatch(value0) {
          this.value0 = value0;
      };
      TypeMismatch.create = function (value0) {
          return new TypeMismatch(value0);
      };
      return TypeMismatch;
  })();
  var UnexpectedValue = (function () {
      function UnexpectedValue(value0) {
          this.value0 = value0;
      };
      UnexpectedValue.create = function (value0) {
          return new UnexpectedValue(value0);
      };
      return UnexpectedValue;
  })();
  var AtIndex = (function () {
      function AtIndex(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      AtIndex.create = function (value0) {
          return function (value1) {
              return new AtIndex(value0, value1);
          };
      };
      return AtIndex;
  })();
  var AtKey = (function () {
      function AtKey(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      AtKey.create = function (value0) {
          return function (value1) {
              return new AtKey(value0, value1);
          };
      };
      return AtKey;
  })();
  var Named = (function () {
      function Named(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Named.create = function (value0) {
          return function (value1) {
              return new Named(value0, value1);
          };
      };
      return Named;
  })();
  var MissingValue = (function () {
      function MissingValue() {

      };
      MissingValue.value = new MissingValue();
      return MissingValue;
  })();
  var printJsonDecodeError = function (err) {
      var go = function (v) {
          if (v instanceof TypeMismatch) {
              return "  Expected value of type '" + (v.value0 + "'.");
          };
          if (v instanceof UnexpectedValue) {
              return "  Unexpected value " + (Data_Argonaut_Core.stringify(v.value0) + ".");
          };
          if (v instanceof AtIndex) {
              return "  At array index " + (Data_Show.show(Data_Show.showInt)(v.value0) + (":\x0a" + go(v.value1)));
          };
          if (v instanceof AtKey) {
              return "  At object key '" + (v.value0 + ("':\x0a" + go(v.value1)));
          };
          if (v instanceof Named) {
              return "  Under '" + (v.value0 + ("':\x0a" + go(v.value1)));
          };
          if (v instanceof MissingValue) {
              return "  No value was found.";
          };
          throw new Error("Failed pattern match at Data.Argonaut.Decode.Error (line 37, column 8 - line 43, column 44): " + [ v.constructor.name ]);
      };
      return "An error occurred while decoding a JSON value:\x0a" + go(err);
  };
  exports["TypeMismatch"] = TypeMismatch;
  exports["AtKey"] = AtKey;
  exports["MissingValue"] = MissingValue;
  exports["printJsonDecodeError"] = printJsonDecodeError;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Argonaut.Decode.Decoders"] = $PS["Data.Argonaut.Decode.Decoders"] || {};
  var exports = $PS["Data.Argonaut.Decode.Decoders"];
  var Data_Argonaut_Core = $PS["Data.Argonaut.Core"];
  var Data_Argonaut_Decode_Error = $PS["Data.Argonaut.Decode.Error"];
  var Data_Either = $PS["Data.Either"];
  var decodeString = Data_Argonaut_Core.caseJsonString(Data_Either.Left.create(new Data_Argonaut_Decode_Error.TypeMismatch("String")))(Data_Either.Right.create);
  exports["decodeString"] = decodeString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Record"] = $PS["Record"] || {};
  var exports = $PS["Record"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Record_Unsafe = $PS["Record.Unsafe"];
  var set = function (dictIsSymbol) {
      return function (dictCons) {
          return function (dictCons1) {
              return function (l) {
                  return function (b) {
                      return function (r) {
                          return Record_Unsafe.unsafeSet(Data_Symbol.reflectSymbol(dictIsSymbol)(l))(b)(r);
                      };
                  };
              };
          };
      };
  };
  var insert = function (dictIsSymbol) {
      return function (dictLacks) {
          return function (dictCons) {
              return function (l) {
                  return function (a) {
                      return function (r) {
                          return Record_Unsafe.unsafeSet(Data_Symbol.reflectSymbol(dictIsSymbol)(l))(a)(r);
                      };
                  };
              };
          };
      };
  };
  var get = function (dictIsSymbol) {
      return function (dictCons) {
          return function (l) {
              return function (r) {
                  return Record_Unsafe.unsafeGet(Data_Symbol.reflectSymbol(dictIsSymbol)(l))(r);
              };
          };
      };
  };
  var $$delete = function (dictIsSymbol) {
      return function (dictLacks) {
          return function (dictCons) {
              return function (l) {
                  return function (r) {
                      return Record_Unsafe.unsafeDelete(Data_Symbol.reflectSymbol(dictIsSymbol)(l))(r);
                  };
              };
          };
      };
  };
  exports["get"] = get;
  exports["set"] = set;
  exports["insert"] = insert;
  exports["delete"] = $$delete;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Argonaut.Decode.Class"] = $PS["Data.Argonaut.Decode.Class"] || {};
  var exports = $PS["Data.Argonaut.Decode.Class"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Argonaut_Core = $PS["Data.Argonaut.Core"];
  var Data_Argonaut_Decode_Decoders = $PS["Data.Argonaut.Decode.Decoders"];
  var Data_Argonaut_Decode_Error = $PS["Data.Argonaut.Decode.Error"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Foreign_Object = $PS["Foreign.Object"];
  var Record = $PS["Record"];
  var Type_Data_RowList = $PS["Type.Data.RowList"];                
  var GDecodeJson = function (gDecodeJson) {
      this.gDecodeJson = gDecodeJson;
  };
  var DecodeJson = function (decodeJson) {
      this.decodeJson = decodeJson;
  };
  var gDecodeJsonNil = new GDecodeJson(function (v) {
      return function (v1) {
          return new Data_Either.Right({});
      };
  });
  var gDecodeJson = function (dict) {
      return dict.gDecodeJson;
  };                                                                        
  var decodeRecord = function (dictGDecodeJson) {
      return function (dictRowToList) {
          return new DecodeJson(function (json) {
              var v = Data_Argonaut_Core.toObject(json);
              if (v instanceof Data_Maybe.Just) {
                  return gDecodeJson(dictGDecodeJson)(v.value0)(Type_Data_RowList.RLProxy.value);
              };
              if (v instanceof Data_Maybe.Nothing) {
                  return Data_Either.Left.create(new Data_Argonaut_Decode_Error.TypeMismatch("Object"));
              };
              throw new Error("Failed pattern match at Data.Argonaut.Decode.Class (line 99, column 5 - line 101, column 46): " + [ v.constructor.name ]);
          });
      };
  };
  var decodeJsonString = new DecodeJson(Data_Argonaut_Decode_Decoders.decodeString);  
  var decodeJson = function (dict) {
      return dict.decodeJson;
  };
  var gDecodeJsonCons = function (dictDecodeJson) {
      return function (dictGDecodeJson) {
          return function (dictIsSymbol) {
              return function (dictCons) {
                  return function (dictLacks) {
                      return new GDecodeJson(function (object) {
                          return function (v) {
                              var fieldName = Data_Symbol.reflectSymbol(dictIsSymbol)(Data_Symbol.SProxy.value);
                              var v1 = Foreign_Object.lookup(fieldName)(object);
                              if (v1 instanceof Data_Maybe.Just) {
                                  return Control_Bind.bind(Data_Either.bindEither)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Argonaut_Decode_Error.AtKey.create(fieldName))(decodeJson(dictDecodeJson)(v1.value0)))(function (val) {
                                      return Control_Bind.bind(Data_Either.bindEither)(gDecodeJson(dictGDecodeJson)(object)(Type_Data_RowList.RLProxy.value))(function (rest) {
                                          return Data_Either.Right.create(Record.insert(dictIsSymbol)()()(Data_Symbol.SProxy.value)(val)(rest));
                                      });
                                  });
                              };
                              if (v1 instanceof Data_Maybe.Nothing) {
                                  return Data_Either.Left.create(new Data_Argonaut_Decode_Error.AtKey(fieldName, Data_Argonaut_Decode_Error.MissingValue.value));
                              };
                              throw new Error("Failed pattern match at Data.Argonaut.Decode.Class (line 122, column 5 - line 129, column 44): " + [ v1.constructor.name ]);
                          };
                      });
                  };
              };
          };
      };
  };
  exports["decodeJson"] = decodeJson;
  exports["DecodeJson"] = DecodeJson;
  exports["decodeJsonString"] = decodeJsonString;
  exports["decodeRecord"] = decodeRecord;
  exports["gDecodeJsonNil"] = gDecodeJsonNil;
  exports["gDecodeJsonCons"] = gDecodeJsonCons;
})(PS);
(function(exports) {
  "use strict";

  // module Unsafe.Coerce

  exports.unsafeCoerce = function (x) {
    return x;
  };
})(PS["Unsafe.Coerce"] = PS["Unsafe.Coerce"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Unsafe.Coerce"] = $PS["Unsafe.Coerce"] || {};
  var exports = $PS["Unsafe.Coerce"];
  var $foreign = $PS["Unsafe.Coerce"];
  exports["unsafeCoerce"] = $foreign.unsafeCoerce;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Array.NonEmpty"] = $PS["Data.Array.NonEmpty"] || {};
  var exports = $PS["Data.Array.NonEmpty"];
  var Data_Array = $PS["Data.Array"];
  var Unsafe_Coerce = $PS["Unsafe.Coerce"];                
  var unsafeFromArrayF = Unsafe_Coerce.unsafeCoerce;
  var some = function (dictAlternative) {
      return function (dictLazy) {
          var $47 = Data_Array.some(dictAlternative)(dictLazy);
          return function ($48) {
              return unsafeFromArrayF($47($48));
          };
      };
  };
  exports["some"] = some;
})(PS);
(function(exports) {
  "use strict";

  exports.fold1Impl = function (f) {
    return function (xs) {
      var acc = xs[0];
      var len = xs.length;
      for (var i = 1; i < len; i++) {
        acc = f(acc)(xs[i]);
      }
      return acc;
    };
  };
})(PS["Data.Array.NonEmpty.Internal"] = PS["Data.Array.NonEmpty.Internal"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Semigroup.Foldable"] = $PS["Data.Semigroup.Foldable"] || {};
  var exports = $PS["Data.Semigroup.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Foldable1 = function (Foldable0, fold1, foldMap1) {
      this.Foldable0 = Foldable0;
      this.fold1 = fold1;
      this.foldMap1 = foldMap1;
  }; 
  var fold1 = function (dict) {
      return dict.fold1;
  };
  var foldMap1Default = function (dictFoldable1) {
      return function (dictFunctor) {
          return function (dictSemigroup) {
              return function (f) {
                  var $45 = fold1(dictFoldable1)(dictSemigroup);
                  var $46 = Data_Functor.map(dictFunctor)(f);
                  return function ($47) {
                      return $45($46($47));
                  };
              };
          };
      };
  };
  exports["Foldable1"] = Foldable1;
  exports["foldMap1Default"] = foldMap1Default;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Array.NonEmpty.Internal"] = $PS["Data.Array.NonEmpty.Internal"] || {};
  var exports = $PS["Data.Array.NonEmpty.Internal"];
  var $foreign = $PS["Data.Array.NonEmpty.Internal"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Semigroup_Foldable = $PS["Data.Semigroup.Foldable"];                   
  var functorNonEmptyArray = Data_Functor.functorArray;                              
  var foldableNonEmptyArray = Data_Foldable.foldableArray;
  var foldable1NonEmptyArray = new Data_Semigroup_Foldable.Foldable1(function () {
      return foldableNonEmptyArray;
  }, function (dictSemigroup) {
      return $foreign.fold1Impl(Data_Semigroup.append(dictSemigroup));
  }, function (dictSemigroup) {
      return Data_Semigroup_Foldable.foldMap1Default(foldable1NonEmptyArray)(functorNonEmptyArray)(dictSemigroup);
  });
  exports["foldable1NonEmptyArray"] = foldable1NonEmptyArray;
})(PS);
(function(exports) {
  "use strict";

  exports.topInt = 2147483647;
  exports.bottomInt = -2147483648;

  exports.topChar = String.fromCharCode(65535);
  exports.bottomChar = String.fromCharCode(0);
})(PS["Data.Bounded"] = PS["Data.Bounded"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Bounded"] = $PS["Data.Bounded"] || {};
  var exports = $PS["Data.Bounded"];
  var $foreign = $PS["Data.Bounded"];
  var Data_Ord = $PS["Data.Ord"];                  
  var Bounded = function (Ord0, bottom, top) {
      this.Ord0 = Ord0;
      this.bottom = bottom;
      this.top = top;
  };
  var top = function (dict) {
      return dict.top;
  };                                            
  var boundedInt = new Bounded(function () {
      return Data_Ord.ordInt;
  }, $foreign.bottomInt, $foreign.topInt);
  var boundedChar = new Bounded(function () {
      return Data_Ord.ordChar;
  }, $foreign.bottomChar, $foreign.topChar);
  var bottom = function (dict) {
      return dict.bottom;
  };
  exports["Bounded"] = Bounded;
  exports["bottom"] = bottom;
  exports["top"] = top;
  exports["boundedInt"] = boundedInt;
  exports["boundedChar"] = boundedChar;
})(PS);
(function(exports) {
  "use strict";

  exports.toCharCode = function (c) {
    return c.charCodeAt(0);
  };

  exports.fromCharCode = function (c) {
    return String.fromCharCode(c);
  };
})(PS["Data.Enum"] = PS["Data.Enum"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Enum"] = $PS["Data.Enum"] || {};
  var exports = $PS["Data.Enum"];
  var $foreign = $PS["Data.Enum"];
  var Data_Bounded = $PS["Data.Bounded"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Enum = function (Ord0, pred, succ) {
      this.Ord0 = Ord0;
      this.pred = pred;
      this.succ = succ;
  };
  var BoundedEnum = function (Bounded0, Enum1, cardinality, fromEnum, toEnum) {
      this.Bounded0 = Bounded0;
      this.Enum1 = Enum1;
      this.cardinality = cardinality;
      this.fromEnum = fromEnum;
      this.toEnum = toEnum;
  };
  var toEnum = function (dict) {
      return dict.toEnum;
  };              
  var fromEnum = function (dict) {
      return dict.fromEnum;
  };
  var toEnumWithDefaults = function (dictBoundedEnum) {
      return function (low) {
          return function (high) {
              return function (x) {
                  var v = toEnum(dictBoundedEnum)(x);
                  if (v instanceof Data_Maybe.Just) {
                      return v.value0;
                  };
                  if (v instanceof Data_Maybe.Nothing) {
                      var $54 = x < fromEnum(dictBoundedEnum)(Data_Bounded.bottom(dictBoundedEnum.Bounded0()));
                      if ($54) {
                          return low;
                      };
                      return high;
                  };
                  throw new Error("Failed pattern match at Data.Enum (line 158, column 33 - line 160, column 62): " + [ v.constructor.name ]);
              };
          };
      };
  };
  var defaultSucc = function (toEnum$prime) {
      return function (fromEnum$prime) {
          return function (a) {
              return toEnum$prime(fromEnum$prime(a) + 1 | 0);
          };
      };
  };
  var defaultPred = function (toEnum$prime) {
      return function (fromEnum$prime) {
          return function (a) {
              return toEnum$prime(fromEnum$prime(a) - 1 | 0);
          };
      };
  };
  var charToEnum = function (v) {
      if (v >= Data_Bounded.bottom(Data_Bounded.boundedInt) && v <= Data_Bounded.top(Data_Bounded.boundedInt)) {
          return new Data_Maybe.Just($foreign.fromCharCode(v));
      };
      return Data_Maybe.Nothing.value;
  };
  var enumChar = new Enum(function () {
      return Data_Ord.ordChar;
  }, defaultPred(charToEnum)($foreign.toCharCode), defaultSucc(charToEnum)($foreign.toCharCode));
  var boundedEnumChar = new BoundedEnum(function () {
      return Data_Bounded.boundedChar;
  }, function () {
      return enumChar;
  }, $foreign.toCharCode(Data_Bounded.top(Data_Bounded.boundedChar)) - $foreign.toCharCode(Data_Bounded.bottom(Data_Bounded.boundedChar)) | 0, $foreign.toCharCode, charToEnum);
  exports["Enum"] = Enum;
  exports["BoundedEnum"] = BoundedEnum;
  exports["toEnum"] = toEnum;
  exports["fromEnum"] = fromEnum;
  exports["toEnumWithDefaults"] = toEnumWithDefaults;
  exports["defaultSucc"] = defaultSucc;
  exports["defaultPred"] = defaultPred;
  exports["boundedEnumChar"] = boundedEnumChar;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Char"] = $PS["Data.Char"] || {};
  var exports = $PS["Data.Char"];
  var Data_Enum = $PS["Data.Enum"];                
  var toCharCode = Data_Enum.fromEnum(Data_Enum.boundedEnumChar);
  exports["toCharCode"] = toCharCode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Char.Unicode"] = $PS["Data.Char.Unicode"] || {};
  var exports = $PS["Data.Char.Unicode"];
  var Data_Char = $PS["Data.Char"];
  var isDigit = function (c) {
      var diff = Data_Char.toCharCode(c) - Data_Char.toCharCode("0") | 0;
      return diff <= 9 && diff >= 0;
  };
  var isHexDigit = function (c) {
      return isDigit(c) || ((function () {
          var diff = Data_Char.toCharCode(c) - Data_Char.toCharCode("A") | 0;
          return diff <= 5 && diff >= 0;
      })() || (function () {
          var diff = Data_Char.toCharCode(c) - Data_Char.toCharCode("a") | 0;
          return diff <= 5 && diff >= 0;
      })());
  };
  exports["isDigit"] = isDigit;
  exports["isHexDigit"] = isHexDigit;
})(PS);
(function(exports) {
  "use strict";

  exports.intSub = function (x) {
    return function (y) {
      /* jshint bitwise: false */
      return x - y | 0;
    };
  };
})(PS["Data.Ring"] = PS["Data.Ring"] || {});
(function(exports) {
  "use strict";

  exports.intAdd = function (x) {
    return function (y) {
      /* jshint bitwise: false */
      return x + y | 0;
    };
  };

  exports.intMul = function (x) {
    return function (y) {
      /* jshint bitwise: false */
      return x * y | 0;
    };
  };
})(PS["Data.Semiring"] = PS["Data.Semiring"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Semiring"] = $PS["Data.Semiring"] || {};
  var exports = $PS["Data.Semiring"];
  var $foreign = $PS["Data.Semiring"];
  var Semiring = function (add, mul, one, zero) {
      this.add = add;
      this.mul = mul;
      this.one = one;
      this.zero = zero;
  };                                                                            
  var semiringInt = new Semiring($foreign.intAdd, $foreign.intMul, 1, 0);
  exports["semiringInt"] = semiringInt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Ring"] = $PS["Data.Ring"] || {};
  var exports = $PS["Data.Ring"];
  var $foreign = $PS["Data.Ring"];
  var Data_Semiring = $PS["Data.Semiring"];
  var Ring = function (Semiring0, sub) {
      this.Semiring0 = Semiring0;
      this.sub = sub;
  };                  
  var ringInt = new Ring(function () {
      return Data_Semiring.semiringInt;
  }, $foreign.intSub);
  exports["ringInt"] = ringInt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.CommutativeRing"] = $PS["Data.CommutativeRing"] || {};
  var exports = $PS["Data.CommutativeRing"];
  var Data_Ring = $PS["Data.Ring"];
  var CommutativeRing = function (Ring0) {
      this.Ring0 = Ring0;
  }; 
  var commutativeRingInt = new CommutativeRing(function () {
      return Data_Ring.ringInt;
  });
  exports["commutativeRingInt"] = commutativeRingInt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Const"] = $PS["Data.Const"] || {};
  var exports = $PS["Data.Const"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];                                      
  var Const = function (x) {
      return x;
  };
  var newtypeConst = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Const);
  var functorConst = new Data_Functor.Functor(function (f) {
      return function (m) {
          return m;
      };
  });
  var applyConst = function (dictSemigroup) {
      return new Control_Apply.Apply(function () {
          return functorConst;
      }, function (v) {
          return function (v1) {
              return Data_Semigroup.append(dictSemigroup)(v)(v1);
          };
      });
  };
  var applicativeConst = function (dictMonoid) {
      return new Control_Applicative.Applicative(function () {
          return applyConst(dictMonoid.Semigroup0());
      }, function (v) {
          return Data_Monoid.mempty(dictMonoid);
      });
  };
  exports["Const"] = Const;
  exports["newtypeConst"] = newtypeConst;
  exports["applicativeConst"] = applicativeConst;
})(PS);
(function(exports) {
  "use strict";

  exports.intDegree = function (x) {
    return Math.min(Math.abs(x), 2147483647);
  };

  // See the Euclidean definition in
  // https://en.m.wikipedia.org/wiki/Modulo_operation.
  exports.intDiv = function (x) {
    return function (y) {
      if (y === 0) return 0;
      return y > 0 ? Math.floor(x / y) : -Math.floor(x / -y);
    };
  };

  exports.intMod = function (x) {
    return function (y) {
      if (y === 0) return 0;
      var yy = Math.abs(y);
      return ((x % yy) + yy) % yy;
    };
  };
})(PS["Data.EuclideanRing"] = PS["Data.EuclideanRing"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.EuclideanRing"] = $PS["Data.EuclideanRing"] || {};
  var exports = $PS["Data.EuclideanRing"];
  var $foreign = $PS["Data.EuclideanRing"];
  var Data_CommutativeRing = $PS["Data.CommutativeRing"];  
  var EuclideanRing = function (CommutativeRing0, degree, div, mod) {
      this.CommutativeRing0 = CommutativeRing0;
      this.degree = degree;
      this.div = div;
      this.mod = mod;
  };
  var mod = function (dict) {
      return dict.mod;
  }; 
  var euclideanRingInt = new EuclideanRing(function () {
      return Data_CommutativeRing.commutativeRingInt;
  }, $foreign.intDegree, $foreign.intDiv, $foreign.intMod);
  var div = function (dict) {
      return dict.div;
  };
  exports["div"] = div;
  exports["mod"] = mod;
  exports["euclideanRingInt"] = euclideanRingInt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.FoldableWithIndex"] = $PS["Data.FoldableWithIndex"] || {};
  var exports = $PS["Data.FoldableWithIndex"];
  var FoldableWithIndex = function (Foldable0, foldMapWithIndex, foldlWithIndex, foldrWithIndex) {
      this.Foldable0 = Foldable0;
      this.foldMapWithIndex = foldMapWithIndex;
      this.foldlWithIndex = foldlWithIndex;
      this.foldrWithIndex = foldrWithIndex;
  };
  exports["FoldableWithIndex"] = FoldableWithIndex;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.FunctorWithIndex"] = $PS["Data.FunctorWithIndex"] || {};
  var exports = $PS["Data.FunctorWithIndex"];      
  var FunctorWithIndex = function (Functor0, mapWithIndex) {
      this.Functor0 = Functor0;
      this.mapWithIndex = mapWithIndex;
  };
  var mapWithIndex = function (dict) {
      return dict.mapWithIndex;
  };
  exports["FunctorWithIndex"] = FunctorWithIndex;
  exports["mapWithIndex"] = mapWithIndex;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Generic.Rep"] = $PS["Data.Generic.Rep"] || {};
  var exports = $PS["Data.Generic.Rep"];             
  var Inl = (function () {
      function Inl(value0) {
          this.value0 = value0;
      };
      Inl.create = function (value0) {
          return new Inl(value0);
      };
      return Inl;
  })();
  var Inr = (function () {
      function Inr(value0) {
          this.value0 = value0;
      };
      Inr.create = function (value0) {
          return new Inr(value0);
      };
      return Inr;
  })();
  var Generic = function (from, to) {
      this.from = from;
      this.to = to;
  }; 
  var from = function (dict) {
      return dict.from;
  };
  exports["Generic"] = Generic;
  exports["from"] = from;
  exports["Inl"] = Inl;
  exports["Inr"] = Inr;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Generic.Rep.Show"] = $PS["Data.Generic.Rep.Show"] || {};
  var exports = $PS["Data.Generic.Rep.Show"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Generic_Rep = $PS["Data.Generic.Rep"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Symbol = $PS["Data.Symbol"];                
  var GenericShowArgs = function (genericShowArgs) {
      this.genericShowArgs = genericShowArgs;
  };
  var GenericShow = function (genericShow$prime) {
      this["genericShow'"] = genericShow$prime;
  }; 
  var genericShowArgsArgument = function (dictShow) {
      return new GenericShowArgs(function (v) {
          return [ Data_Show.show(dictShow)(v) ];
      });
  };
  var genericShowArgs = function (dict) {
      return dict.genericShowArgs;
  };
  var genericShowConstructor = function (dictGenericShowArgs) {
      return function (dictIsSymbol) {
          return new GenericShow(function (v) {
              var ctor = Data_Symbol.reflectSymbol(dictIsSymbol)(Data_Symbol.SProxy.value);
              var v1 = genericShowArgs(dictGenericShowArgs)(v);
              if (v1.length === 0) {
                  return ctor;
              };
              return "(" + (Data_Foldable.intercalate(Data_Foldable.foldableArray)(Data_Monoid.monoidString)(" ")(Data_Semigroup.append(Data_Semigroup.semigroupArray)([ ctor ])(v1)) + ")");
          });
      };
  };
  var genericShow$prime = function (dict) {
      return dict["genericShow'"];
  }; 
  var genericShowSum = function (dictGenericShow) {
      return function (dictGenericShow1) {
          return new GenericShow(function (v) {
              if (v instanceof Data_Generic_Rep.Inl) {
                  return genericShow$prime(dictGenericShow)(v.value0);
              };
              if (v instanceof Data_Generic_Rep.Inr) {
                  return genericShow$prime(dictGenericShow1)(v.value0);
              };
              throw new Error("Failed pattern match at Data.Generic.Rep.Show (line 26, column 1 - line 28, column 40): " + [ v.constructor.name ]);
          });
      };
  };
  var genericShow = function (dictGeneric) {
      return function (dictGenericShow) {
          return function (x) {
              return genericShow$prime(dictGenericShow)(Data_Generic_Rep.from(dictGeneric)(x));
          };
      };
  };
  exports["genericShow"] = genericShow;
  exports["genericShowSum"] = genericShowSum;
  exports["genericShowConstructor"] = genericShowConstructor;
  exports["genericShowArgsArgument"] = genericShowArgsArgument;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Lens.Internal.Wander"] = $PS["Data.Lens.Internal.Wander"] || {};
  var exports = $PS["Data.Lens.Internal.Wander"];                            
  var Wander = function (Choice1, Strong0, wander) {
      this.Choice1 = Choice1;
      this.Strong0 = Strong0;
      this.wander = wander;
  }; 
  var wander = function (dict) {
      return dict.wander;
  };
  exports["wander"] = wander;
  exports["Wander"] = Wander;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Profunctor"] = $PS["Data.Profunctor"] || {};
  var exports = $PS["Data.Profunctor"];                  
  var Profunctor = function (dimap) {
      this.dimap = dimap;
  }; 
  var dimap = function (dict) {
      return dict.dimap;
  };
  exports["dimap"] = dimap;
  exports["Profunctor"] = Profunctor;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Profunctor.Choice"] = $PS["Data.Profunctor.Choice"] || {};
  var exports = $PS["Data.Profunctor.Choice"];                 
  var Choice = function (Profunctor0, left, right) {
      this.Profunctor0 = Profunctor0;
      this.left = left;
      this.right = right;
  };
  exports["Choice"] = Choice;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Profunctor.Strong"] = $PS["Data.Profunctor.Strong"] || {};
  var exports = $PS["Data.Profunctor.Strong"];       
  var Strong = function (Profunctor0, first, second) {
      this.Profunctor0 = Profunctor0;
      this.first = first;
      this.second = second;
  };
  var first = function (dict) {
      return dict.first;
  };
  exports["first"] = first;
  exports["Strong"] = Strong;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Lens.Internal.Forget"] = $PS["Data.Lens.Internal.Forget"] || {};
  var exports = $PS["Data.Lens.Internal.Forget"];
  var Data_Const = $PS["Data.Const"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Lens_Internal_Wander = $PS["Data.Lens.Internal.Wander"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Profunctor = $PS["Data.Profunctor"];
  var Data_Profunctor_Choice = $PS["Data.Profunctor.Choice"];
  var Data_Profunctor_Strong = $PS["Data.Profunctor.Strong"];
  var Data_Tuple = $PS["Data.Tuple"];                
  var Forget = function (x) {
      return x;
  };
  var profunctorForget = new Data_Profunctor.Profunctor(function (f) {
      return function (v) {
          return function (v1) {
              return function ($27) {
                  return v1(f($27));
              };
          };
      };
  });
  var strongForget = new Data_Profunctor_Strong.Strong(function () {
      return profunctorForget;
  }, function (v) {
      return function ($28) {
          return v(Data_Tuple.fst($28));
      };
  }, function (v) {
      return function ($29) {
          return v(Data_Tuple.snd($29));
      };
  });
  var newtypeForget = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Forget);
  var choiceForget = function (dictMonoid) {
      return new Data_Profunctor_Choice.Choice(function () {
          return profunctorForget;
      }, function (v) {
          return Data_Either.either(v)(Data_Monoid.mempty(Data_Monoid.monoidFn(dictMonoid)));
      }, function (v) {
          return Data_Either.either(Data_Monoid.mempty(Data_Monoid.monoidFn(dictMonoid)))(v);
      });
  };
  var wanderForget = function (dictMonoid) {
      return new Data_Lens_Internal_Wander.Wander(function () {
          return choiceForget(dictMonoid);
      }, function () {
          return strongForget;
      }, function (f) {
          return function (v) {
              return Data_Newtype.alaF(Data_Functor.functorFn)(Data_Functor.functorFn)(Data_Const.newtypeConst)(Data_Const.newtypeConst)(Data_Const.Const)(f(Data_Const.applicativeConst(dictMonoid)))(v);
          };
      });
  };
  exports["Forget"] = Forget;
  exports["newtypeForget"] = newtypeForget;
  exports["strongForget"] = strongForget;
  exports["wanderForget"] = wanderForget;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Maybe.Last"] = $PS["Data.Maybe.Last"] || {};
  var exports = $PS["Data.Maybe.Last"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];      
  var Last = function (x) {
      return x;
  };
  var semigroupLast = new Data_Semigroup.Semigroup(function (v) {
      return function (v1) {
          if (v1 instanceof Data_Maybe.Just) {
              return v1;
          };
          if (v1 instanceof Data_Maybe.Nothing) {
              return v;
          };
          throw new Error("Failed pattern match at Data.Maybe.Last (line 52, column 1 - line 54, column 36): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });                                 
  var newtypeLast = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Last);
  var monoidLast = new Data_Monoid.Monoid(function () {
      return semigroupLast;
  }, Data_Maybe.Nothing.value);
  exports["Last"] = Last;
  exports["newtypeLast"] = newtypeLast;
  exports["monoidLast"] = monoidLast;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Lens.Fold"] = $PS["Data.Lens.Fold"] || {};
  var exports = $PS["Data.Lens.Fold"];
  var Data_Lens_Internal_Forget = $PS["Data.Lens.Internal.Forget"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Maybe_Last = $PS["Data.Maybe.Last"];
  var Data_Newtype = $PS["Data.Newtype"];
  var foldMapOf = Data_Newtype.under(Data_Lens_Internal_Forget.newtypeForget)(Data_Lens_Internal_Forget.newtypeForget)(Data_Lens_Internal_Forget.Forget);
  var lastOf = function (p) {
      var $91 = Data_Newtype.unwrap(Data_Maybe_Last.newtypeLast);
      var $92 = foldMapOf(p)(function ($94) {
          return Data_Maybe_Last.Last(Data_Maybe.Just.create($94));
      });
      return function ($93) {
          return $91($92($93));
      };
  };
  exports["lastOf"] = lastOf;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Lens.Lens"] = $PS["Data.Lens.Lens"] || {};
  var exports = $PS["Data.Lens.Lens"];
  var Data_Profunctor = $PS["Data.Profunctor"];
  var Data_Profunctor_Strong = $PS["Data.Profunctor.Strong"];
  var Data_Tuple = $PS["Data.Tuple"];
  var lens$prime = function (to) {
      return function (dictStrong) {
          return function (pab) {
              return Data_Profunctor.dimap(dictStrong.Profunctor0())(to)(function (v) {
                  return v.value1(v.value0);
              })(Data_Profunctor_Strong.first(dictStrong)(pab));
          };
      };
  };
  var lens = function (get) {
      return function (set) {
          return function (dictStrong) {
              return lens$prime(function (s) {
                  return new Data_Tuple.Tuple(get(s), function (b) {
                      return set(s)(b);
                  });
              })(dictStrong);
          };
      };
  };
  exports["lens"] = lens;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.TraversableWithIndex"] = $PS["Data.TraversableWithIndex"] || {};
  var exports = $PS["Data.TraversableWithIndex"];  
  var TraversableWithIndex = function (FoldableWithIndex1, FunctorWithIndex0, Traversable2, traverseWithIndex) {
      this.FoldableWithIndex1 = FoldableWithIndex1;
      this.FunctorWithIndex0 = FunctorWithIndex0;
      this.Traversable2 = Traversable2;
      this.traverseWithIndex = traverseWithIndex;
  };
  var traverseWithIndex = function (dict) {
      return dict.traverseWithIndex;
  };
  exports["TraversableWithIndex"] = TraversableWithIndex;
  exports["traverseWithIndex"] = traverseWithIndex;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Map.Internal"] = $PS["Data.Map.Internal"] || {};
  var exports = $PS["Data.Map.Internal"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Category = $PS["Control.Category"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_FoldableWithIndex = $PS["Data.FoldableWithIndex"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_FunctorWithIndex = $PS["Data.FunctorWithIndex"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Ordering = $PS["Data.Ordering"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Traversable = $PS["Data.Traversable"];
  var Data_TraversableWithIndex = $PS["Data.TraversableWithIndex"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unfoldable = $PS["Data.Unfoldable"];                
  var Leaf = (function () {
      function Leaf() {

      };
      Leaf.value = new Leaf();
      return Leaf;
  })();
  var Two = (function () {
      function Two(value0, value1, value2, value3) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
      };
      Two.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return new Two(value0, value1, value2, value3);
                  };
              };
          };
      };
      return Two;
  })();
  var Three = (function () {
      function Three(value0, value1, value2, value3, value4, value5, value6) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
          this.value4 = value4;
          this.value5 = value5;
          this.value6 = value6;
      };
      Three.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return function (value4) {
                          return function (value5) {
                              return function (value6) {
                                  return new Three(value0, value1, value2, value3, value4, value5, value6);
                              };
                          };
                      };
                  };
              };
          };
      };
      return Three;
  })();
  var TwoLeft = (function () {
      function TwoLeft(value0, value1, value2) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
      };
      TwoLeft.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return new TwoLeft(value0, value1, value2);
              };
          };
      };
      return TwoLeft;
  })();
  var TwoRight = (function () {
      function TwoRight(value0, value1, value2) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
      };
      TwoRight.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return new TwoRight(value0, value1, value2);
              };
          };
      };
      return TwoRight;
  })();
  var ThreeLeft = (function () {
      function ThreeLeft(value0, value1, value2, value3, value4, value5) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
          this.value4 = value4;
          this.value5 = value5;
      };
      ThreeLeft.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return function (value4) {
                          return function (value5) {
                              return new ThreeLeft(value0, value1, value2, value3, value4, value5);
                          };
                      };
                  };
              };
          };
      };
      return ThreeLeft;
  })();
  var ThreeMiddle = (function () {
      function ThreeMiddle(value0, value1, value2, value3, value4, value5) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
          this.value4 = value4;
          this.value5 = value5;
      };
      ThreeMiddle.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return function (value4) {
                          return function (value5) {
                              return new ThreeMiddle(value0, value1, value2, value3, value4, value5);
                          };
                      };
                  };
              };
          };
      };
      return ThreeMiddle;
  })();
  var ThreeRight = (function () {
      function ThreeRight(value0, value1, value2, value3, value4, value5) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
          this.value4 = value4;
          this.value5 = value5;
      };
      ThreeRight.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return function (value4) {
                          return function (value5) {
                              return new ThreeRight(value0, value1, value2, value3, value4, value5);
                          };
                      };
                  };
              };
          };
      };
      return ThreeRight;
  })();
  var KickUp = (function () {
      function KickUp(value0, value1, value2, value3) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
      };
      KickUp.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return new KickUp(value0, value1, value2, value3);
                  };
              };
          };
      };
      return KickUp;
  })();
  var values = function (v) {
      if (v instanceof Leaf) {
          return Data_List_Types.Nil.value;
      };
      if (v instanceof Two) {
          return Data_Semigroup.append(Data_List_Types.semigroupList)(values(v.value0))(Data_Semigroup.append(Data_List_Types.semigroupList)(Control_Applicative.pure(Data_List_Types.applicativeList)(v.value2))(values(v.value3)));
      };
      if (v instanceof Three) {
          return Data_Semigroup.append(Data_List_Types.semigroupList)(values(v.value0))(Data_Semigroup.append(Data_List_Types.semigroupList)(Control_Applicative.pure(Data_List_Types.applicativeList)(v.value2))(Data_Semigroup.append(Data_List_Types.semigroupList)(values(v.value3))(Data_Semigroup.append(Data_List_Types.semigroupList)(Control_Applicative.pure(Data_List_Types.applicativeList)(v.value5))(values(v.value6)))));
      };
      throw new Error("Failed pattern match at Data.Map.Internal (line 612, column 1 - line 612, column 40): " + [ v.constructor.name ]);
  };
  var singleton = function (k) {
      return function (v) {
          return new Two(Leaf.value, k, v, Leaf.value);
      };
  };
  var toUnfoldable = function (dictUnfoldable) {
      return function (m) {
          var go = function ($copy_v) {
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(v) {
                  if (v instanceof Data_List_Types.Nil) {
                      $tco_done = true;
                      return Data_Maybe.Nothing.value;
                  };
                  if (v instanceof Data_List_Types.Cons) {
                      if (v.value0 instanceof Leaf) {
                          $copy_v = v.value1;
                          return;
                      };
                      if (v.value0 instanceof Two && (v.value0.value0 instanceof Leaf && v.value0.value3 instanceof Leaf)) {
                          $tco_done = true;
                          return Data_Maybe.Just.create(new Data_Tuple.Tuple(new Data_Tuple.Tuple(v.value0.value1, v.value0.value2), v.value1));
                      };
                      if (v.value0 instanceof Two && v.value0.value0 instanceof Leaf) {
                          $tco_done = true;
                          return Data_Maybe.Just.create(new Data_Tuple.Tuple(new Data_Tuple.Tuple(v.value0.value1, v.value0.value2), new Data_List_Types.Cons(v.value0.value3, v.value1)));
                      };
                      if (v.value0 instanceof Two) {
                          $copy_v = new Data_List_Types.Cons(v.value0.value0, new Data_List_Types.Cons(singleton(v.value0.value1)(v.value0.value2), new Data_List_Types.Cons(v.value0.value3, v.value1)));
                          return;
                      };
                      if (v.value0 instanceof Three) {
                          $copy_v = new Data_List_Types.Cons(v.value0.value0, new Data_List_Types.Cons(singleton(v.value0.value1)(v.value0.value2), new Data_List_Types.Cons(v.value0.value3, new Data_List_Types.Cons(singleton(v.value0.value4)(v.value0.value5), new Data_List_Types.Cons(v.value0.value6, v.value1)))));
                          return;
                      };
                      throw new Error("Failed pattern match at Data.Map.Internal (line 577, column 18 - line 586, column 71): " + [ v.value0.constructor.name ]);
                  };
                  throw new Error("Failed pattern match at Data.Map.Internal (line 576, column 3 - line 576, column 19): " + [ v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($copy_v);
              };
              return $tco_result;
          };
          return Data_Unfoldable.unfoldr(dictUnfoldable)(go)(new Data_List_Types.Cons(m, Data_List_Types.Nil.value));
      };
  };
  var lookup = function (dictOrd) {
      return function (k) {
          var comp = Data_Ord.compare(dictOrd);
          var go = function ($copy_v) {
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(v) {
                  if (v instanceof Leaf) {
                      $tco_done = true;
                      return Data_Maybe.Nothing.value;
                  };
                  if (v instanceof Two) {
                      var v2 = comp(k)(v.value1);
                      if (v2 instanceof Data_Ordering.EQ) {
                          $tco_done = true;
                          return new Data_Maybe.Just(v.value2);
                      };
                      if (v2 instanceof Data_Ordering.LT) {
                          $copy_v = v.value0;
                          return;
                      };
                      $copy_v = v.value3;
                      return;
                  };
                  if (v instanceof Three) {
                      var v3 = comp(k)(v.value1);
                      if (v3 instanceof Data_Ordering.EQ) {
                          $tco_done = true;
                          return new Data_Maybe.Just(v.value2);
                      };
                      var v4 = comp(k)(v.value4);
                      if (v4 instanceof Data_Ordering.EQ) {
                          $tco_done = true;
                          return new Data_Maybe.Just(v.value5);
                      };
                      if (v3 instanceof Data_Ordering.LT) {
                          $copy_v = v.value0;
                          return;
                      };
                      if (v4 instanceof Data_Ordering.GT) {
                          $copy_v = v.value6;
                          return;
                      };
                      $copy_v = v.value3;
                      return;
                  };
                  throw new Error("Failed pattern match at Data.Map.Internal (line 200, column 5 - line 200, column 22): " + [ v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($copy_v);
              };
              return $tco_result;
          };
          return go;
      };
  };
  var member = function (dictOrd) {
      return function (k) {
          return function (m) {
              return Data_Maybe.isJust(lookup(dictOrd)(k)(m));
          };
      };
  };
  var functorMap = new Data_Functor.Functor(function (v) {
      return function (v1) {
          if (v1 instanceof Leaf) {
              return Leaf.value;
          };
          if (v1 instanceof Two) {
              return new Two(Data_Functor.map(functorMap)(v)(v1.value0), v1.value1, v(v1.value2), Data_Functor.map(functorMap)(v)(v1.value3));
          };
          if (v1 instanceof Three) {
              return new Three(Data_Functor.map(functorMap)(v)(v1.value0), v1.value1, v(v1.value2), Data_Functor.map(functorMap)(v)(v1.value3), v1.value4, v(v1.value5), Data_Functor.map(functorMap)(v)(v1.value6));
          };
          throw new Error("Failed pattern match at Data.Map.Internal (line 96, column 1 - line 99, column 110): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var functorWithIndexMap = new Data_FunctorWithIndex.FunctorWithIndex(function () {
      return functorMap;
  }, function (v) {
      return function (v1) {
          if (v1 instanceof Leaf) {
              return Leaf.value;
          };
          if (v1 instanceof Two) {
              return new Two(Data_FunctorWithIndex.mapWithIndex(functorWithIndexMap)(v)(v1.value0), v1.value1, v(v1.value1)(v1.value2), Data_FunctorWithIndex.mapWithIndex(functorWithIndexMap)(v)(v1.value3));
          };
          if (v1 instanceof Three) {
              return new Three(Data_FunctorWithIndex.mapWithIndex(functorWithIndexMap)(v)(v1.value0), v1.value1, v(v1.value1)(v1.value2), Data_FunctorWithIndex.mapWithIndex(functorWithIndexMap)(v)(v1.value3), v1.value4, v(v1.value4)(v1.value5), Data_FunctorWithIndex.mapWithIndex(functorWithIndexMap)(v)(v1.value6));
          };
          throw new Error("Failed pattern match at Data.Map.Internal (line 101, column 1 - line 104, column 152): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var fromZipper = function ($copy_dictOrd) {
      return function ($copy_v) {
          return function ($copy_tree) {
              var $tco_var_dictOrd = $copy_dictOrd;
              var $tco_var_v = $copy_v;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(dictOrd, v, tree) {
                  if (v instanceof Data_List_Types.Nil) {
                      $tco_done = true;
                      return tree;
                  };
                  if (v instanceof Data_List_Types.Cons) {
                      if (v.value0 instanceof TwoLeft) {
                          $tco_var_dictOrd = dictOrd;
                          $tco_var_v = v.value1;
                          $copy_tree = new Two(tree, v.value0.value0, v.value0.value1, v.value0.value2);
                          return;
                      };
                      if (v.value0 instanceof TwoRight) {
                          $tco_var_dictOrd = dictOrd;
                          $tco_var_v = v.value1;
                          $copy_tree = new Two(v.value0.value0, v.value0.value1, v.value0.value2, tree);
                          return;
                      };
                      if (v.value0 instanceof ThreeLeft) {
                          $tco_var_dictOrd = dictOrd;
                          $tco_var_v = v.value1;
                          $copy_tree = new Three(tree, v.value0.value0, v.value0.value1, v.value0.value2, v.value0.value3, v.value0.value4, v.value0.value5);
                          return;
                      };
                      if (v.value0 instanceof ThreeMiddle) {
                          $tco_var_dictOrd = dictOrd;
                          $tco_var_v = v.value1;
                          $copy_tree = new Three(v.value0.value0, v.value0.value1, v.value0.value2, tree, v.value0.value3, v.value0.value4, v.value0.value5);
                          return;
                      };
                      if (v.value0 instanceof ThreeRight) {
                          $tco_var_dictOrd = dictOrd;
                          $tco_var_v = v.value1;
                          $copy_tree = new Three(v.value0.value0, v.value0.value1, v.value0.value2, v.value0.value3, v.value0.value4, v.value0.value5, tree);
                          return;
                      };
                      throw new Error("Failed pattern match at Data.Map.Internal (line 418, column 3 - line 423, column 88): " + [ v.value0.constructor.name ]);
                  };
                  throw new Error("Failed pattern match at Data.Map.Internal (line 415, column 1 - line 415, column 80): " + [ v.constructor.name, tree.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_dictOrd, $tco_var_v, $copy_tree);
              };
              return $tco_result;
          };
      };
  };
  var insert = function (dictOrd) {
      return function (k) {
          return function (v) {
              var up = function ($copy_v1) {
                  return function ($copy_v2) {
                      var $tco_var_v1 = $copy_v1;
                      var $tco_done = false;
                      var $tco_result;
                      function $tco_loop(v1, v2) {
                          if (v1 instanceof Data_List_Types.Nil) {
                              $tco_done = true;
                              return new Two(v2.value0, v2.value1, v2.value2, v2.value3);
                          };
                          if (v1 instanceof Data_List_Types.Cons) {
                              if (v1.value0 instanceof TwoLeft) {
                                  $tco_done = true;
                                  return fromZipper(dictOrd)(v1.value1)(new Three(v2.value0, v2.value1, v2.value2, v2.value3, v1.value0.value0, v1.value0.value1, v1.value0.value2));
                              };
                              if (v1.value0 instanceof TwoRight) {
                                  $tco_done = true;
                                  return fromZipper(dictOrd)(v1.value1)(new Three(v1.value0.value0, v1.value0.value1, v1.value0.value2, v2.value0, v2.value1, v2.value2, v2.value3));
                              };
                              if (v1.value0 instanceof ThreeLeft) {
                                  $tco_var_v1 = v1.value1;
                                  $copy_v2 = new KickUp(new Two(v2.value0, v2.value1, v2.value2, v2.value3), v1.value0.value0, v1.value0.value1, new Two(v1.value0.value2, v1.value0.value3, v1.value0.value4, v1.value0.value5));
                                  return;
                              };
                              if (v1.value0 instanceof ThreeMiddle) {
                                  $tco_var_v1 = v1.value1;
                                  $copy_v2 = new KickUp(new Two(v1.value0.value0, v1.value0.value1, v1.value0.value2, v2.value0), v2.value1, v2.value2, new Two(v2.value3, v1.value0.value3, v1.value0.value4, v1.value0.value5));
                                  return;
                              };
                              if (v1.value0 instanceof ThreeRight) {
                                  $tco_var_v1 = v1.value1;
                                  $copy_v2 = new KickUp(new Two(v1.value0.value0, v1.value0.value1, v1.value0.value2, v1.value0.value3), v1.value0.value4, v1.value0.value5, new Two(v2.value0, v2.value1, v2.value2, v2.value3));
                                  return;
                              };
                              throw new Error("Failed pattern match at Data.Map.Internal (line 454, column 5 - line 459, column 108): " + [ v1.value0.constructor.name, v2.constructor.name ]);
                          };
                          throw new Error("Failed pattern match at Data.Map.Internal (line 451, column 3 - line 451, column 56): " + [ v1.constructor.name, v2.constructor.name ]);
                      };
                      while (!$tco_done) {
                          $tco_result = $tco_loop($tco_var_v1, $copy_v2);
                      };
                      return $tco_result;
                  };
              };
              var comp = Data_Ord.compare(dictOrd);
              var down = function ($copy_ctx) {
                  return function ($copy_v1) {
                      var $tco_var_ctx = $copy_ctx;
                      var $tco_done = false;
                      var $tco_result;
                      function $tco_loop(ctx, v1) {
                          if (v1 instanceof Leaf) {
                              $tco_done = true;
                              return up(ctx)(new KickUp(Leaf.value, k, v, Leaf.value));
                          };
                          if (v1 instanceof Two) {
                              var v2 = comp(k)(v1.value1);
                              if (v2 instanceof Data_Ordering.EQ) {
                                  $tco_done = true;
                                  return fromZipper(dictOrd)(ctx)(new Two(v1.value0, k, v, v1.value3));
                              };
                              if (v2 instanceof Data_Ordering.LT) {
                                  $tco_var_ctx = new Data_List_Types.Cons(new TwoLeft(v1.value1, v1.value2, v1.value3), ctx);
                                  $copy_v1 = v1.value0;
                                  return;
                              };
                              $tco_var_ctx = new Data_List_Types.Cons(new TwoRight(v1.value0, v1.value1, v1.value2), ctx);
                              $copy_v1 = v1.value3;
                              return;
                          };
                          if (v1 instanceof Three) {
                              var v3 = comp(k)(v1.value1);
                              if (v3 instanceof Data_Ordering.EQ) {
                                  $tco_done = true;
                                  return fromZipper(dictOrd)(ctx)(new Three(v1.value0, k, v, v1.value3, v1.value4, v1.value5, v1.value6));
                              };
                              var v4 = comp(k)(v1.value4);
                              if (v4 instanceof Data_Ordering.EQ) {
                                  $tco_done = true;
                                  return fromZipper(dictOrd)(ctx)(new Three(v1.value0, v1.value1, v1.value2, v1.value3, k, v, v1.value6));
                              };
                              if (v3 instanceof Data_Ordering.LT) {
                                  $tco_var_ctx = new Data_List_Types.Cons(new ThreeLeft(v1.value1, v1.value2, v1.value3, v1.value4, v1.value5, v1.value6), ctx);
                                  $copy_v1 = v1.value0;
                                  return;
                              };
                              if (v3 instanceof Data_Ordering.GT && v4 instanceof Data_Ordering.LT) {
                                  $tco_var_ctx = new Data_List_Types.Cons(new ThreeMiddle(v1.value0, v1.value1, v1.value2, v1.value4, v1.value5, v1.value6), ctx);
                                  $copy_v1 = v1.value3;
                                  return;
                              };
                              $tco_var_ctx = new Data_List_Types.Cons(new ThreeRight(v1.value0, v1.value1, v1.value2, v1.value3, v1.value4, v1.value5), ctx);
                              $copy_v1 = v1.value6;
                              return;
                          };
                          throw new Error("Failed pattern match at Data.Map.Internal (line 434, column 3 - line 434, column 55): " + [ ctx.constructor.name, v1.constructor.name ]);
                      };
                      while (!$tco_done) {
                          $tco_result = $tco_loop($tco_var_ctx, $copy_v1);
                      };
                      return $tco_result;
                  };
              };
              return down(Data_List_Types.Nil.value);
          };
      };
  };
  var pop = function (dictOrd) {
      return function (k) {
          var up = function ($copy_ctxs) {
              return function ($copy_tree) {
                  var $tco_var_ctxs = $copy_ctxs;
                  var $tco_done = false;
                  var $tco_result;
                  function $tco_loop(ctxs, tree) {
                      if (ctxs instanceof Data_List_Types.Nil) {
                          $tco_done = true;
                          return tree;
                      };
                      if (ctxs instanceof Data_List_Types.Cons) {
                          if (ctxs.value0 instanceof TwoLeft && (ctxs.value0.value2 instanceof Leaf && tree instanceof Leaf)) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(Leaf.value, ctxs.value0.value0, ctxs.value0.value1, Leaf.value));
                          };
                          if (ctxs.value0 instanceof TwoRight && (ctxs.value0.value0 instanceof Leaf && tree instanceof Leaf)) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(Leaf.value, ctxs.value0.value1, ctxs.value0.value2, Leaf.value));
                          };
                          if (ctxs.value0 instanceof TwoLeft && ctxs.value0.value2 instanceof Two) {
                              $tco_var_ctxs = ctxs.value1;
                              $copy_tree = new Three(tree, ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2.value0, ctxs.value0.value2.value1, ctxs.value0.value2.value2, ctxs.value0.value2.value3);
                              return;
                          };
                          if (ctxs.value0 instanceof TwoRight && ctxs.value0.value0 instanceof Two) {
                              $tco_var_ctxs = ctxs.value1;
                              $copy_tree = new Three(ctxs.value0.value0.value0, ctxs.value0.value0.value1, ctxs.value0.value0.value2, ctxs.value0.value0.value3, ctxs.value0.value1, ctxs.value0.value2, tree);
                              return;
                          };
                          if (ctxs.value0 instanceof TwoLeft && ctxs.value0.value2 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(new Two(tree, ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2.value0), ctxs.value0.value2.value1, ctxs.value0.value2.value2, new Two(ctxs.value0.value2.value3, ctxs.value0.value2.value4, ctxs.value0.value2.value5, ctxs.value0.value2.value6)));
                          };
                          if (ctxs.value0 instanceof TwoRight && ctxs.value0.value0 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(new Two(ctxs.value0.value0.value0, ctxs.value0.value0.value1, ctxs.value0.value0.value2, ctxs.value0.value0.value3), ctxs.value0.value0.value4, ctxs.value0.value0.value5, new Two(ctxs.value0.value0.value6, ctxs.value0.value1, ctxs.value0.value2, tree)));
                          };
                          if (ctxs.value0 instanceof ThreeLeft && (ctxs.value0.value2 instanceof Leaf && (ctxs.value0.value5 instanceof Leaf && tree instanceof Leaf))) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(Leaf.value, ctxs.value0.value0, ctxs.value0.value1, Leaf.value, ctxs.value0.value3, ctxs.value0.value4, Leaf.value));
                          };
                          if (ctxs.value0 instanceof ThreeMiddle && (ctxs.value0.value0 instanceof Leaf && (ctxs.value0.value5 instanceof Leaf && tree instanceof Leaf))) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(Leaf.value, ctxs.value0.value1, ctxs.value0.value2, Leaf.value, ctxs.value0.value3, ctxs.value0.value4, Leaf.value));
                          };
                          if (ctxs.value0 instanceof ThreeRight && (ctxs.value0.value0 instanceof Leaf && (ctxs.value0.value3 instanceof Leaf && tree instanceof Leaf))) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(Leaf.value, ctxs.value0.value1, ctxs.value0.value2, Leaf.value, ctxs.value0.value4, ctxs.value0.value5, Leaf.value));
                          };
                          if (ctxs.value0 instanceof ThreeLeft && ctxs.value0.value2 instanceof Two) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(new Three(tree, ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2.value0, ctxs.value0.value2.value1, ctxs.value0.value2.value2, ctxs.value0.value2.value3), ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5));
                          };
                          if (ctxs.value0 instanceof ThreeMiddle && ctxs.value0.value0 instanceof Two) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(new Three(ctxs.value0.value0.value0, ctxs.value0.value0.value1, ctxs.value0.value0.value2, ctxs.value0.value0.value3, ctxs.value0.value1, ctxs.value0.value2, tree), ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5));
                          };
                          if (ctxs.value0 instanceof ThreeMiddle && ctxs.value0.value5 instanceof Two) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2, new Three(tree, ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5.value0, ctxs.value0.value5.value1, ctxs.value0.value5.value2, ctxs.value0.value5.value3)));
                          };
                          if (ctxs.value0 instanceof ThreeRight && ctxs.value0.value3 instanceof Two) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Two(ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2, new Three(ctxs.value0.value3.value0, ctxs.value0.value3.value1, ctxs.value0.value3.value2, ctxs.value0.value3.value3, ctxs.value0.value4, ctxs.value0.value5, tree)));
                          };
                          if (ctxs.value0 instanceof ThreeLeft && ctxs.value0.value2 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(new Two(tree, ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2.value0), ctxs.value0.value2.value1, ctxs.value0.value2.value2, new Two(ctxs.value0.value2.value3, ctxs.value0.value2.value4, ctxs.value0.value2.value5, ctxs.value0.value2.value6), ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5));
                          };
                          if (ctxs.value0 instanceof ThreeMiddle && ctxs.value0.value0 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(new Two(ctxs.value0.value0.value0, ctxs.value0.value0.value1, ctxs.value0.value0.value2, ctxs.value0.value0.value3), ctxs.value0.value0.value4, ctxs.value0.value0.value5, new Two(ctxs.value0.value0.value6, ctxs.value0.value1, ctxs.value0.value2, tree), ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5));
                          };
                          if (ctxs.value0 instanceof ThreeMiddle && ctxs.value0.value5 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2, new Two(tree, ctxs.value0.value3, ctxs.value0.value4, ctxs.value0.value5.value0), ctxs.value0.value5.value1, ctxs.value0.value5.value2, new Two(ctxs.value0.value5.value3, ctxs.value0.value5.value4, ctxs.value0.value5.value5, ctxs.value0.value5.value6)));
                          };
                          if (ctxs.value0 instanceof ThreeRight && ctxs.value0.value3 instanceof Three) {
                              $tco_done = true;
                              return fromZipper(dictOrd)(ctxs.value1)(new Three(ctxs.value0.value0, ctxs.value0.value1, ctxs.value0.value2, new Two(ctxs.value0.value3.value0, ctxs.value0.value3.value1, ctxs.value0.value3.value2, ctxs.value0.value3.value3), ctxs.value0.value3.value4, ctxs.value0.value3.value5, new Two(ctxs.value0.value3.value6, ctxs.value0.value4, ctxs.value0.value5, tree)));
                          };
                          throw new Error("Failed pattern match at Data.Map.Internal (line 511, column 9 - line 528, column 136): " + [ ctxs.value0.constructor.name, tree.constructor.name ]);
                      };
                      throw new Error("Failed pattern match at Data.Map.Internal (line 508, column 5 - line 528, column 136): " + [ ctxs.constructor.name ]);
                  };
                  while (!$tco_done) {
                      $tco_result = $tco_loop($tco_var_ctxs, $copy_tree);
                  };
                  return $tco_result;
              };
          };
          var removeMaxNode = function ($copy_ctx) {
              return function ($copy_m) {
                  var $tco_var_ctx = $copy_ctx;
                  var $tco_done = false;
                  var $tco_result;
                  function $tco_loop(ctx, m) {
                      if (m instanceof Two && (m.value0 instanceof Leaf && m.value3 instanceof Leaf)) {
                          $tco_done = true;
                          return up(ctx)(Leaf.value);
                      };
                      if (m instanceof Two) {
                          $tco_var_ctx = new Data_List_Types.Cons(new TwoRight(m.value0, m.value1, m.value2), ctx);
                          $copy_m = m.value3;
                          return;
                      };
                      if (m instanceof Three && (m.value0 instanceof Leaf && (m.value3 instanceof Leaf && m.value6 instanceof Leaf))) {
                          $tco_done = true;
                          return up(new Data_List_Types.Cons(new TwoRight(Leaf.value, m.value1, m.value2), ctx))(Leaf.value);
                      };
                      if (m instanceof Three) {
                          $tco_var_ctx = new Data_List_Types.Cons(new ThreeRight(m.value0, m.value1, m.value2, m.value3, m.value4, m.value5), ctx);
                          $copy_m = m.value6;
                          return;
                      };
                      throw new Error("Failed pattern match at Data.Map.Internal (line 540, column 5 - line 544, column 107): " + [ m.constructor.name ]);
                  };
                  while (!$tco_done) {
                      $tco_result = $tco_loop($tco_var_ctx, $copy_m);
                  };
                  return $tco_result;
              };
          };
          var maxNode = function ($copy_m) {
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(m) {
                  if (m instanceof Two && m.value3 instanceof Leaf) {
                      $tco_done = true;
                      return {
                          key: m.value1,
                          value: m.value2
                      };
                  };
                  if (m instanceof Two) {
                      $copy_m = m.value3;
                      return;
                  };
                  if (m instanceof Three && m.value6 instanceof Leaf) {
                      $tco_done = true;
                      return {
                          key: m.value4,
                          value: m.value5
                      };
                  };
                  if (m instanceof Three) {
                      $copy_m = m.value6;
                      return;
                  };
                  throw new Error("Failed pattern match at Data.Map.Internal (line 531, column 33 - line 535, column 45): " + [ m.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($copy_m);
              };
              return $tco_result;
          };
          var comp = Data_Ord.compare(dictOrd);
          var down = function ($copy_ctx) {
              return function ($copy_m) {
                  var $tco_var_ctx = $copy_ctx;
                  var $tco_done = false;
                  var $tco_result;
                  function $tco_loop(ctx, m) {
                      if (m instanceof Leaf) {
                          $tco_done = true;
                          return Data_Maybe.Nothing.value;
                      };
                      if (m instanceof Two) {
                          var v = comp(k)(m.value1);
                          if (m.value3 instanceof Leaf && v instanceof Data_Ordering.EQ) {
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value2, up(ctx)(Leaf.value)));
                          };
                          if (v instanceof Data_Ordering.EQ) {
                              var max = maxNode(m.value0);
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value2, removeMaxNode(new Data_List_Types.Cons(new TwoLeft(max.key, max.value, m.value3), ctx))(m.value0)));
                          };
                          if (v instanceof Data_Ordering.LT) {
                              $tco_var_ctx = new Data_List_Types.Cons(new TwoLeft(m.value1, m.value2, m.value3), ctx);
                              $copy_m = m.value0;
                              return;
                          };
                          $tco_var_ctx = new Data_List_Types.Cons(new TwoRight(m.value0, m.value1, m.value2), ctx);
                          $copy_m = m.value3;
                          return;
                      };
                      if (m instanceof Three) {
                          var leaves = (function () {
                              if (m.value0 instanceof Leaf && (m.value3 instanceof Leaf && m.value6 instanceof Leaf)) {
                                  return true;
                              };
                              return false;
                          })();
                          var v = comp(k)(m.value4);
                          var v3 = comp(k)(m.value1);
                          if (leaves && v3 instanceof Data_Ordering.EQ) {
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value2, fromZipper(dictOrd)(ctx)(new Two(Leaf.value, m.value4, m.value5, Leaf.value))));
                          };
                          if (leaves && v instanceof Data_Ordering.EQ) {
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value5, fromZipper(dictOrd)(ctx)(new Two(Leaf.value, m.value1, m.value2, Leaf.value))));
                          };
                          if (v3 instanceof Data_Ordering.EQ) {
                              var max = maxNode(m.value0);
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value2, removeMaxNode(new Data_List_Types.Cons(new ThreeLeft(max.key, max.value, m.value3, m.value4, m.value5, m.value6), ctx))(m.value0)));
                          };
                          if (v instanceof Data_Ordering.EQ) {
                              var max = maxNode(m.value3);
                              $tco_done = true;
                              return new Data_Maybe.Just(new Data_Tuple.Tuple(m.value5, removeMaxNode(new Data_List_Types.Cons(new ThreeMiddle(m.value0, m.value1, m.value2, max.key, max.value, m.value6), ctx))(m.value3)));
                          };
                          if (v3 instanceof Data_Ordering.LT) {
                              $tco_var_ctx = new Data_List_Types.Cons(new ThreeLeft(m.value1, m.value2, m.value3, m.value4, m.value5, m.value6), ctx);
                              $copy_m = m.value0;
                              return;
                          };
                          if (v3 instanceof Data_Ordering.GT && v instanceof Data_Ordering.LT) {
                              $tco_var_ctx = new Data_List_Types.Cons(new ThreeMiddle(m.value0, m.value1, m.value2, m.value4, m.value5, m.value6), ctx);
                              $copy_m = m.value3;
                              return;
                          };
                          $tco_var_ctx = new Data_List_Types.Cons(new ThreeRight(m.value0, m.value1, m.value2, m.value3, m.value4, m.value5), ctx);
                          $copy_m = m.value6;
                          return;
                      };
                      throw new Error("Failed pattern match at Data.Map.Internal (line 481, column 34 - line 504, column 80): " + [ m.constructor.name ]);
                  };
                  while (!$tco_done) {
                      $tco_result = $tco_loop($tco_var_ctx, $copy_m);
                  };
                  return $tco_result;
              };
          };
          return down(Data_List_Types.Nil.value);
      };
  };
  var foldableMap = new Data_Foldable.Foldable(function (dictMonoid) {
      return function (f) {
          return function (m) {
              return Data_Foldable.foldMap(Data_List_Types.foldableList)(dictMonoid)(f)(values(m));
          };
      };
  }, function (f) {
      return function (z) {
          return function (m) {
              return Data_Foldable.foldl(Data_List_Types.foldableList)(f)(z)(values(m));
          };
      };
  }, function (f) {
      return function (z) {
          return function (m) {
              return Data_Foldable.foldr(Data_List_Types.foldableList)(f)(z)(values(m));
          };
      };
  });
  var traversableMap = new Data_Traversable.Traversable(function () {
      return foldableMap;
  }, function () {
      return functorMap;
  }, function (dictApplicative) {
      return Data_Traversable.traverse(traversableMap)(dictApplicative)(Control_Category.identity(Control_Category.categoryFn));
  }, function (dictApplicative) {
      return function (f) {
          return function (v) {
              if (v instanceof Leaf) {
                  return Control_Applicative.pure(dictApplicative)(Leaf.value);
              };
              if (v instanceof Two) {
                  return Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Data_Functor.map((dictApplicative.Apply0()).Functor0())(Two.create)(Data_Traversable.traverse(traversableMap)(dictApplicative)(f)(v.value0)))(Control_Applicative.pure(dictApplicative)(v.value1)))(f(v.value2)))(Data_Traversable.traverse(traversableMap)(dictApplicative)(f)(v.value3));
              };
              if (v instanceof Three) {
                  return Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Data_Functor.map((dictApplicative.Apply0()).Functor0())(Three.create)(Data_Traversable.traverse(traversableMap)(dictApplicative)(f)(v.value0)))(Control_Applicative.pure(dictApplicative)(v.value1)))(f(v.value2)))(Data_Traversable.traverse(traversableMap)(dictApplicative)(f)(v.value3)))(Control_Applicative.pure(dictApplicative)(v.value4)))(f(v.value5)))(Data_Traversable.traverse(traversableMap)(dictApplicative)(f)(v.value6));
              };
              throw new Error("Failed pattern match at Data.Map.Internal (line 119, column 1 - line 134, column 31): " + [ f.constructor.name, v.constructor.name ]);
          };
      };
  });
  var empty = Leaf.value;
  var fromFoldable = function (dictOrd) {
      return function (dictFoldable) {
          return Data_Foldable.foldl(dictFoldable)(function (m) {
              return function (v) {
                  return insert(dictOrd)(v.value0)(v.value1)(m);
              };
          })(empty);
      };
  };
  var $$delete = function (dictOrd) {
      return function (k) {
          return function (m) {
              return Data_Maybe.maybe(m)(Data_Tuple.snd)(pop(dictOrd)(k)(m));
          };
      };
  };
  var asList = Control_Category.identity(Control_Category.categoryFn);
  var foldableWithIndexMap = new Data_FoldableWithIndex.FoldableWithIndex(function () {
      return foldableMap;
  }, function (dictMonoid) {
      return function (f) {
          return function (m) {
              return Data_Foldable.foldMap(Data_List_Types.foldableList)(dictMonoid)(Data_Tuple.uncurry(f))(asList(toUnfoldable(Data_List_Types.unfoldableList)(m)));
          };
      };
  }, function (f) {
      return function (z) {
          return function (m) {
              return Data_Foldable.foldl(Data_List_Types.foldableList)((function () {
                  var $763 = Data_Function.flip(f);
                  return function ($764) {
                      return Data_Tuple.uncurry($763($764));
                  };
              })())(z)(asList(toUnfoldable(Data_List_Types.unfoldableList)(m)));
          };
      };
  }, function (f) {
      return function (z) {
          return function (m) {
              return Data_Foldable.foldr(Data_List_Types.foldableList)(Data_Tuple.uncurry(f))(z)(asList(toUnfoldable(Data_List_Types.unfoldableList)(m)));
          };
      };
  });
  var traversableWithIndexMap = new Data_TraversableWithIndex.TraversableWithIndex(function () {
      return foldableWithIndexMap;
  }, function () {
      return functorWithIndexMap;
  }, function () {
      return traversableMap;
  }, function (dictApplicative) {
      return function (f) {
          return function (v) {
              if (v instanceof Leaf) {
                  return Control_Applicative.pure(dictApplicative)(Leaf.value);
              };
              if (v instanceof Two) {
                  return Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Data_Functor.map((dictApplicative.Apply0()).Functor0())(Two.create)(Data_TraversableWithIndex.traverseWithIndex(traversableWithIndexMap)(dictApplicative)(f)(v.value0)))(Control_Applicative.pure(dictApplicative)(v.value1)))(f(v.value1)(v.value2)))(Data_TraversableWithIndex.traverseWithIndex(traversableWithIndexMap)(dictApplicative)(f)(v.value3));
              };
              if (v instanceof Three) {
                  return Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Control_Apply.apply(dictApplicative.Apply0())(Data_Functor.map((dictApplicative.Apply0()).Functor0())(Three.create)(Data_TraversableWithIndex.traverseWithIndex(traversableWithIndexMap)(dictApplicative)(f)(v.value0)))(Control_Applicative.pure(dictApplicative)(v.value1)))(f(v.value1)(v.value2)))(Data_TraversableWithIndex.traverseWithIndex(traversableWithIndexMap)(dictApplicative)(f)(v.value3)))(Control_Applicative.pure(dictApplicative)(v.value4)))(f(v.value4)(v.value5)))(Data_TraversableWithIndex.traverseWithIndex(traversableWithIndexMap)(dictApplicative)(f)(v.value6));
              };
              throw new Error("Failed pattern match at Data.Map.Internal (line 136, column 1 - line 150, column 40): " + [ f.constructor.name, v.constructor.name ]);
          };
      };
  });
  var alter = function (dictOrd) {
      return function (f) {
          return function (k) {
              return function (m) {
                  var v = f(lookup(dictOrd)(k)(m));
                  if (v instanceof Data_Maybe.Nothing) {
                      return $$delete(dictOrd)(k)(m);
                  };
                  if (v instanceof Data_Maybe.Just) {
                      return insert(dictOrd)(k)(v.value0)(m);
                  };
                  throw new Error("Failed pattern match at Data.Map.Internal (line 549, column 15 - line 551, column 25): " + [ v.constructor.name ]);
              };
          };
      };
  };
  var unionWith = function (dictOrd) {
      return function (f) {
          return function (m1) {
              return function (m2) {
                  var go = function (m) {
                      return function (v) {
                          return alter(dictOrd)((function () {
                              var $769 = Data_Maybe.maybe(v.value1)(f(v.value1));
                              return function ($770) {
                                  return Data_Maybe.Just.create($769($770));
                              };
                          })())(v.value0)(m);
                      };
                  };
                  return Data_Foldable.foldl(Data_List_Types.foldableList)(go)(m2)(toUnfoldable(Data_List_Types.unfoldableList)(m1));
              };
          };
      };
  };
  var union = function (dictOrd) {
      return unionWith(dictOrd)(Data_Function["const"]);
  };
  exports["empty"] = empty;
  exports["singleton"] = singleton;
  exports["insert"] = insert;
  exports["lookup"] = lookup;
  exports["fromFoldable"] = fromFoldable;
  exports["member"] = member;
  exports["union"] = union;
  exports["traversableWithIndexMap"] = traversableWithIndexMap;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.Set"] = $PS["Data.Set"] || {};
  var exports = $PS["Data.Set"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Map_Internal = $PS["Data.Map.Internal"];
  var Data_Unit = $PS["Data.Unit"];
  var member = function (dictOrd) {
      return function (a) {
          return function (v) {
              return Data_Map_Internal.member(dictOrd)(a)(v);
          };
      };
  };
  var insert = function (dictOrd) {
      return function (a) {
          return function (v) {
              return Data_Map_Internal.insert(dictOrd)(a)(Data_Unit.unit)(v);
          };
      };
  }; 
  var empty = Data_Map_Internal.empty;
  var fromFoldable = function (dictFoldable) {
      return function (dictOrd) {
          return Data_Foldable.foldl(dictFoldable)(function (m) {
              return function (a) {
                  return insert(dictOrd)(a)(m);
              };
          })(empty);
      };
  };
  exports["fromFoldable"] = fromFoldable;
  exports["member"] = member;
})(PS);
(function(exports) {
  "use strict";

  // Encode a string to its Base64 representation using Node's `Buffer` API
  function encodeNodeImpl (str) {
    var base64EncodedString = Buffer.from(str).toString("base64");

    return base64EncodedString;
  };

  // Decode a Base64-encoded string using Node's `Buffer` API
  function decodeNodeImpl (Left, Right, str) {
    var result;

    // Check that the input string is a valid Base64-encoded string as Node.js
    // decided that it would be a good idea to NOT throw on invalid input strings
    // but return an empty buffer instead which cannot be distinguished from the
    // empty string case.
    var reEmptyString = "^$";
    var leadingQuanta = "^([A-Za-z0-9+/]{4})*";
    var finalQuantum =
      "([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}(?:=)?|[A-Za-z0-9+/]{2}(?:=){0,2})$";
    var reValidBase64 =
      new RegExp([reEmptyString, "|", leadingQuanta, finalQuantum].join(""));

    try {
      if (!reValidBase64.test(str)) { throw new Error("Invalid input string");}
      result = Right(Buffer.from(str, "base64").toString("utf-8"));
    }
    catch (error) {
      result = Left(error);
    }

    return result;
  };

  function atobImpl (Left, Right, str) {
    var result;

    try {
      result = Right(atob(str));
    }
    catch (error) {
      result = Left(error);
    }

    return result;
  };

  function btoaImpl (Left, Right, str) {
    var result;

    try {
      result = Right(btoa(str));
    }
    catch (error) {
      result = Left(error);
    }

    return result;
  };                                      
  exports.decodeNodeImpl = decodeNodeImpl;
  exports.atobImpl       = atobImpl;
})(PS["Data.String.Base64"] = PS["Data.String.Base64"] || {});
(function(exports) {
  "use strict";

  var atobIsDefined = typeof atob === "function";

  // This function converts a `Uint8Array` to a btoa-safe string.
  // It does so by treating each byte as a Unicode code point value and by
  // concatenating the corresponding characters.
  // This means that e.g. a three-byte UTF-8 character is mapped to three
  // different characters with code points between 0 .. U+00FF.
  // This is also the reason why `String.fromCharCode` is perfectly safe here.
  function uint8ArrayToBtoaSafeStringImpl (u8) {
    var chunkSize = 0x8000; // Chunk size used for reading large arrays
    var cs = [];

    for (var i = 0; i < u8.length; i += chunkSize) {
      cs.push(String.fromCharCode.apply(null, u8.subarray(i, i + chunkSize)));
    }

    return cs.join("");
  };

  // Inspired by `purescript-typedarray`. Unfortunately, the future of that
  // library is currently (2018-07-18) uncertain.
  function asUint8ArrayImpl (array) {
    return new Uint8Array(array);
  }

  exports.atobIsDefined                  = atobIsDefined;                 
  exports.asUint8ArrayImpl               = asUint8ArrayImpl;
})(PS["Data.String.Base64.Internal"] = PS["Data.String.Base64.Internal"] || {});
(function(exports) {
  "use strict";
  /* global Symbol */

  var hasArrayFrom = typeof Array.from === "function";
  var hasStringIterator =
    typeof Symbol !== "undefined" &&
    Symbol != null &&
    typeof Symbol.iterator !== "undefined" &&
    typeof String.prototype[Symbol.iterator] === "function";
  var hasFromCodePoint = typeof String.prototype.fromCodePoint === "function";
  var hasCodePointAt = typeof String.prototype.codePointAt === "function";

  exports._unsafeCodePointAt0 = function (fallback) {
    return hasCodePointAt
      ? function (str) { return str.codePointAt(0); }
      : fallback;
  };

  exports._singleton = function (fallback) {
    return hasFromCodePoint ? String.fromCodePoint : fallback;
  };

  exports._take = function (fallback) {
    return function (n) {
      if (hasStringIterator) {
        return function (str) {
          var accum = "";
          var iter = str[Symbol.iterator]();
          for (var i = 0; i < n; ++i) {
            var o = iter.next();
            if (o.done) return accum;
            accum += o.value;
          }
          return accum;
        };
      }
      return fallback(n);
    };
  };

  exports._toCodePointArray = function (fallback) {
    return function (unsafeCodePointAt0) {
      if (hasArrayFrom) {
        return function (str) {
          return Array.from(str, unsafeCodePointAt0);
        };
      }
      return fallback;
    };
  };
})(PS["Data.String.CodePoints"] = PS["Data.String.CodePoints"] || {});
(function(exports) {
  "use strict";

  exports.fromCharArray = function (a) {
    return a.join("");
  };

  exports.toCharArray = function (s) {
    return s.split("");
  };

  exports.singleton = function (c) {
    return c;
  };

  exports._charAt = function (just) {
    return function (nothing) {
      return function (i) {
        return function (s) {
          return i >= 0 && i < s.length ? just(s.charAt(i)) : nothing;
        };
      };
    };
  };

  exports.length = function (s) {
    return s.length;
  };

  exports._indexOf = function (just) {
    return function (nothing) {
      return function (x) {
        return function (s) {
          var i = s.indexOf(x);
          return i === -1 ? nothing : just(i);
        };
      };
    };
  };

  exports.take = function (n) {
    return function (s) {
      return s.substr(0, n);
    };
  };

  exports.drop = function (n) {
    return function (s) {
      return s.substring(n);
    };
  };

  exports.splitAt = function (i) {
    return function (s) {
      return { before: s.substring(0, i), after: s.substring(i) };
    };
  };
})(PS["Data.String.CodeUnits"] = PS["Data.String.CodeUnits"] || {});
(function(exports) {
  "use strict";

  exports.charAt = function (i) {
    return function (s) {
      if (i >= 0 && i < s.length) return s.charAt(i);
      throw new Error("Data.String.Unsafe.charAt: Invalid index.");
    };
  };
})(PS["Data.String.Unsafe"] = PS["Data.String.Unsafe"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.Unsafe"] = $PS["Data.String.Unsafe"] || {};
  var exports = $PS["Data.String.Unsafe"];
  var $foreign = $PS["Data.String.Unsafe"];
  exports["charAt"] = $foreign.charAt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.CodeUnits"] = $PS["Data.String.CodeUnits"] || {};
  var exports = $PS["Data.String.CodeUnits"];
  var $foreign = $PS["Data.String.CodeUnits"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Unsafe = $PS["Data.String.Unsafe"];                
  var uncons = function (v) {
      if (v === "") {
          return Data_Maybe.Nothing.value;
      };
      return new Data_Maybe.Just({
          head: Data_String_Unsafe.charAt(0)(v),
          tail: $foreign.drop(1)(v)
      });
  };                                                                                                   
  var indexOf = $foreign["_indexOf"](Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  var charAt = $foreign["_charAt"](Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  exports["uncons"] = uncons;
  exports["indexOf"] = indexOf;
  exports["singleton"] = $foreign.singleton;
  exports["fromCharArray"] = $foreign.fromCharArray;
  exports["toCharArray"] = $foreign.toCharArray;
  exports["length"] = $foreign.length;
  exports["take"] = $foreign.take;
  exports["drop"] = $foreign.drop;
  exports["splitAt"] = $foreign.splitAt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.CodePoints"] = $PS["Data.String.CodePoints"] || {};
  var exports = $PS["Data.String.CodePoints"];
  var $foreign = $PS["Data.String.CodePoints"];
  var Data_Array = $PS["Data.Array"];
  var Data_Boolean = $PS["Data.Boolean"];
  var Data_Bounded = $PS["Data.Bounded"];
  var Data_Enum = $PS["Data.Enum"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_EuclideanRing = $PS["Data.EuclideanRing"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_String_Unsafe = $PS["Data.String.Unsafe"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unfoldable = $PS["Data.Unfoldable"];
  var unsurrogate = function (lead) {
      return function (trail) {
          return (((lead - 55296 | 0) * 1024 | 0) + (trail - 56320 | 0) | 0) + 65536 | 0;
      };
  }; 
  var isTrail = function (cu) {
      return 56320 <= cu && cu <= 57343;
  };
  var isLead = function (cu) {
      return 55296 <= cu && cu <= 56319;
  };
  var uncons = function (s) {
      var v = Data_String_CodeUnits.length(s);
      if (v === 0) {
          return Data_Maybe.Nothing.value;
      };
      if (v === 1) {
          return new Data_Maybe.Just({
              head: Data_Enum.fromEnum(Data_Enum.boundedEnumChar)(Data_String_Unsafe.charAt(0)(s)),
              tail: ""
          });
      };
      var cu1 = Data_Enum.fromEnum(Data_Enum.boundedEnumChar)(Data_String_Unsafe.charAt(1)(s));
      var cu0 = Data_Enum.fromEnum(Data_Enum.boundedEnumChar)(Data_String_Unsafe.charAt(0)(s));
      var $21 = isLead(cu0) && isTrail(cu1);
      if ($21) {
          return new Data_Maybe.Just({
              head: unsurrogate(cu0)(cu1),
              tail: Data_String_CodeUnits.drop(2)(s)
          });
      };
      return new Data_Maybe.Just({
          head: cu0,
          tail: Data_String_CodeUnits.drop(1)(s)
      });
  };
  var unconsButWithTuple = function (s) {
      return Data_Functor.map(Data_Maybe.functorMaybe)(function (v) {
          return new Data_Tuple.Tuple(v.head, v.tail);
      })(uncons(s));
  };
  var toCodePointArrayFallback = function (s) {
      return Data_Unfoldable.unfoldr(Data_Unfoldable.unfoldableArray)(unconsButWithTuple)(s);
  };
  var unsafeCodePointAt0Fallback = function (s) {
      var cu0 = Data_Enum.fromEnum(Data_Enum.boundedEnumChar)(Data_String_Unsafe.charAt(0)(s));
      var $25 = isLead(cu0) && Data_String_CodeUnits.length(s) > 1;
      if ($25) {
          var cu1 = Data_Enum.fromEnum(Data_Enum.boundedEnumChar)(Data_String_Unsafe.charAt(1)(s));
          var $26 = isTrail(cu1);
          if ($26) {
              return unsurrogate(cu0)(cu1);
          };
          return cu0;
      };
      return cu0;
  };
  var unsafeCodePointAt0 = $foreign["_unsafeCodePointAt0"](unsafeCodePointAt0Fallback);
  var toCodePointArray = $foreign["_toCodePointArray"](toCodePointArrayFallback)(unsafeCodePointAt0);
  var length = function ($52) {
      return Data_Array.length(toCodePointArray($52));
  };
  var indexOf = function (p) {
      return function (s) {
          return Data_Functor.map(Data_Maybe.functorMaybe)(function (i) {
              return length(Data_String_CodeUnits.take(i)(s));
          })(Data_String_CodeUnits.indexOf(p)(s));
      };
  };
  var fromCharCode = (function () {
      var $53 = Data_Enum.toEnumWithDefaults(Data_Enum.boundedEnumChar)(Data_Bounded.bottom(Data_Bounded.boundedChar))(Data_Bounded.top(Data_Bounded.boundedChar));
      return function ($54) {
          return Data_String_CodeUnits.singleton($53($54));
      };
  })();
  var singletonFallback = function (v) {
      if (v <= 65535) {
          return fromCharCode(v);
      };
      var lead = Data_EuclideanRing.div(Data_EuclideanRing.euclideanRingInt)(v - 65536 | 0)(1024) + 55296 | 0;
      var trail = Data_EuclideanRing.mod(Data_EuclideanRing.euclideanRingInt)(v - 65536 | 0)(1024) + 56320 | 0;
      return fromCharCode(lead) + fromCharCode(trail);
  };                                                                          
  var singleton = $foreign["_singleton"](singletonFallback);
  var takeFallback = function (n) {
      return function (v) {
          if (n < 1) {
              return "";
          };
          var v1 = uncons(v);
          if (v1 instanceof Data_Maybe.Just) {
              return singleton(v1.value0.head) + takeFallback(n - 1 | 0)(v1.value0.tail);
          };
          return v;
      };
  };
  var take = $foreign["_take"](takeFallback);
  var eqCodePoint = new Data_Eq.Eq(function (x) {
      return function (y) {
          return x === y;
      };
  });
  var ordCodePoint = new Data_Ord.Ord(function () {
      return eqCodePoint;
  }, function (x) {
      return function (y) {
          return Data_Ord.compare(Data_Ord.ordInt)(x)(y);
      };
  });
  var drop = function (n) {
      return function (s) {
          return Data_String_CodeUnits.drop(Data_String_CodeUnits.length(take(n)(s)))(s);
      };
  };
  var boundedCodePoint = new Data_Bounded.Bounded(function () {
      return ordCodePoint;
  }, 0, 1114111);
  var boundedEnumCodePoint = new Data_Enum.BoundedEnum(function () {
      return boundedCodePoint;
  }, function () {
      return enumCodePoint;
  }, 1114111 + 1 | 0, function (v) {
      return v;
  }, function (n) {
      if (n >= 0 && n <= 1114111) {
          return new Data_Maybe.Just(n);
      };
      if (Data_Boolean.otherwise) {
          return Data_Maybe.Nothing.value;
      };
      throw new Error("Failed pattern match at Data.String.CodePoints (line 63, column 1 - line 68, column 26): " + [ n.constructor.name ]);
  });
  var enumCodePoint = new Data_Enum.Enum(function () {
      return ordCodePoint;
  }, Data_Enum.defaultPred(Data_Enum.toEnum(boundedEnumCodePoint))(Data_Enum.fromEnum(boundedEnumCodePoint)), Data_Enum.defaultSucc(Data_Enum.toEnum(boundedEnumCodePoint))(Data_Enum.fromEnum(boundedEnumCodePoint)));
  exports["toCodePointArray"] = toCodePointArray;
  exports["length"] = length;
  exports["indexOf"] = indexOf;
  exports["drop"] = drop;
  exports["boundedEnumCodePoint"] = boundedEnumCodePoint;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.Base64.Internal"] = $PS["Data.String.Base64.Internal"] || {};
  var exports = $PS["Data.String.Base64.Internal"];
  var $foreign = $PS["Data.String.Base64.Internal"];
  var Data_Enum = $PS["Data.Enum"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_String_CodePoints = $PS["Data.String.CodePoints"];
  var Data_String_Common = $PS["Data.String.Common"];
  var toRfc4648 = (function () {
      var $4 = Data_String_Common.replaceAll("-")("+");
      var $5 = Data_String_Common.replaceAll("_")("/");
      return function ($6) {
          return $4($5($6));
      };
  })();
  var asUint8Array = function (arr) {
      return $foreign.asUint8ArrayImpl(arr);
  };
  var unsafeStringToUint8ArrayOfCharCodes = (function () {
      var $7 = Data_Functor.map(Data_Functor.functorArray)(Data_Enum.fromEnum(Data_String_CodePoints.boundedEnumCodePoint));
      return function ($8) {
          return asUint8Array($7(Data_String_CodePoints.toCodePointArray($8)));
      };
  })();
  exports["unsafeStringToUint8ArrayOfCharCodes"] = unsafeStringToUint8ArrayOfCharCodes;
  exports["toRfc4648"] = toRfc4648;
  exports["atobIsDefined"] = $foreign.atobIsDefined;
})(PS);
(function(exports) {
  "use strict";

  exports.decodeImpl = function (Left, Right, utfLabel, buffer) {
    var result;
    var decoder = new TextDecoder(utfLabel);

    try {
      result = Right(decoder.decode(buffer));
    }
    catch (error) {
      result = Left(error);
    }

    return result;
  };
})(PS["Data.TextDecoder"] = PS["Data.TextDecoder"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.TextDecoder"] = $PS["Data.TextDecoder"] || {};
  var exports = $PS["Data.TextDecoder"];
  var $foreign = $PS["Data.TextDecoder"];
  var Data_Either = $PS["Data.Either"];
  var Data_Show = $PS["Data.Show"];                
  var Utf8 = (function () {
      function Utf8() {

      };
      Utf8.value = new Utf8();
      return Utf8;
  })();
  var Ibm866 = (function () {
      function Ibm866() {

      };
      Ibm866.value = new Ibm866();
      return Ibm866;
  })();
  var Iso_8859_2 = (function () {
      function Iso_8859_2() {

      };
      Iso_8859_2.value = new Iso_8859_2();
      return Iso_8859_2;
  })();
  var Iso_8859_3 = (function () {
      function Iso_8859_3() {

      };
      Iso_8859_3.value = new Iso_8859_3();
      return Iso_8859_3;
  })();
  var Iso_8859_4 = (function () {
      function Iso_8859_4() {

      };
      Iso_8859_4.value = new Iso_8859_4();
      return Iso_8859_4;
  })();
  var Iso_8859_5 = (function () {
      function Iso_8859_5() {

      };
      Iso_8859_5.value = new Iso_8859_5();
      return Iso_8859_5;
  })();
  var Iso_8859_6 = (function () {
      function Iso_8859_6() {

      };
      Iso_8859_6.value = new Iso_8859_6();
      return Iso_8859_6;
  })();
  var Iso_8859_7 = (function () {
      function Iso_8859_7() {

      };
      Iso_8859_7.value = new Iso_8859_7();
      return Iso_8859_7;
  })();
  var Iso_8859_8 = (function () {
      function Iso_8859_8() {

      };
      Iso_8859_8.value = new Iso_8859_8();
      return Iso_8859_8;
  })();
  var Iso_8859_8_I = (function () {
      function Iso_8859_8_I() {

      };
      Iso_8859_8_I.value = new Iso_8859_8_I();
      return Iso_8859_8_I;
  })();
  var Iso_8859_10 = (function () {
      function Iso_8859_10() {

      };
      Iso_8859_10.value = new Iso_8859_10();
      return Iso_8859_10;
  })();
  var Iso_8859_13 = (function () {
      function Iso_8859_13() {

      };
      Iso_8859_13.value = new Iso_8859_13();
      return Iso_8859_13;
  })();
  var Iso_8859_14 = (function () {
      function Iso_8859_14() {

      };
      Iso_8859_14.value = new Iso_8859_14();
      return Iso_8859_14;
  })();
  var Iso_8859_15 = (function () {
      function Iso_8859_15() {

      };
      Iso_8859_15.value = new Iso_8859_15();
      return Iso_8859_15;
  })();
  var Iso_8859_16 = (function () {
      function Iso_8859_16() {

      };
      Iso_8859_16.value = new Iso_8859_16();
      return Iso_8859_16;
  })();
  var Koi8_R = (function () {
      function Koi8_R() {

      };
      Koi8_R.value = new Koi8_R();
      return Koi8_R;
  })();
  var Koi8_U = (function () {
      function Koi8_U() {

      };
      Koi8_U.value = new Koi8_U();
      return Koi8_U;
  })();
  var Macintosh = (function () {
      function Macintosh() {

      };
      Macintosh.value = new Macintosh();
      return Macintosh;
  })();
  var Windows_874 = (function () {
      function Windows_874() {

      };
      Windows_874.value = new Windows_874();
      return Windows_874;
  })();
  var Windows_1250 = (function () {
      function Windows_1250() {

      };
      Windows_1250.value = new Windows_1250();
      return Windows_1250;
  })();
  var Windows_1251 = (function () {
      function Windows_1251() {

      };
      Windows_1251.value = new Windows_1251();
      return Windows_1251;
  })();
  var Windows_1252 = (function () {
      function Windows_1252() {

      };
      Windows_1252.value = new Windows_1252();
      return Windows_1252;
  })();
  var Windows_1253 = (function () {
      function Windows_1253() {

      };
      Windows_1253.value = new Windows_1253();
      return Windows_1253;
  })();
  var Windows_1254 = (function () {
      function Windows_1254() {

      };
      Windows_1254.value = new Windows_1254();
      return Windows_1254;
  })();
  var Windows_1255 = (function () {
      function Windows_1255() {

      };
      Windows_1255.value = new Windows_1255();
      return Windows_1255;
  })();
  var Windows_1256 = (function () {
      function Windows_1256() {

      };
      Windows_1256.value = new Windows_1256();
      return Windows_1256;
  })();
  var Windows_1257 = (function () {
      function Windows_1257() {

      };
      Windows_1257.value = new Windows_1257();
      return Windows_1257;
  })();
  var Windows_1258 = (function () {
      function Windows_1258() {

      };
      Windows_1258.value = new Windows_1258();
      return Windows_1258;
  })();
  var X_Mac_Cyrillic = (function () {
      function X_Mac_Cyrillic() {

      };
      X_Mac_Cyrillic.value = new X_Mac_Cyrillic();
      return X_Mac_Cyrillic;
  })();
  var Gbk = (function () {
      function Gbk() {

      };
      Gbk.value = new Gbk();
      return Gbk;
  })();
  var Gb18030 = (function () {
      function Gb18030() {

      };
      Gb18030.value = new Gb18030();
      return Gb18030;
  })();
  var Big5 = (function () {
      function Big5() {

      };
      Big5.value = new Big5();
      return Big5;
  })();
  var Euc_Jp = (function () {
      function Euc_Jp() {

      };
      Euc_Jp.value = new Euc_Jp();
      return Euc_Jp;
  })();
  var Iso_2022_Jp = (function () {
      function Iso_2022_Jp() {

      };
      Iso_2022_Jp.value = new Iso_2022_Jp();
      return Iso_2022_Jp;
  })();
  var Shift_Jis = (function () {
      function Shift_Jis() {

      };
      Shift_Jis.value = new Shift_Jis();
      return Shift_Jis;
  })();
  var Euc_Kr = (function () {
      function Euc_Kr() {

      };
      Euc_Kr.value = new Euc_Kr();
      return Euc_Kr;
  })();
  var Replacement = (function () {
      function Replacement() {

      };
      Replacement.value = new Replacement();
      return Replacement;
  })();
  var Utf_16Be = (function () {
      function Utf_16Be() {

      };
      Utf_16Be.value = new Utf_16Be();
      return Utf_16Be;
  })();
  var Utf_16Le = (function () {
      function Utf_16Le() {

      };
      Utf_16Le.value = new Utf_16Le();
      return Utf_16Le;
  })();
  var X_User_Defined = (function () {
      function X_User_Defined() {

      };
      X_User_Defined.value = new X_User_Defined();
      return X_User_Defined;
  })();
  var showEncoding = new Data_Show.Show(function (v) {
      if (v instanceof Utf8) {
          return "utf-8";
      };
      if (v instanceof Ibm866) {
          return "ibm866";
      };
      if (v instanceof Iso_8859_2) {
          return "iso-8859-2";
      };
      if (v instanceof Iso_8859_3) {
          return "iso-8859-3";
      };
      if (v instanceof Iso_8859_4) {
          return "iso-8859-4";
      };
      if (v instanceof Iso_8859_5) {
          return "iso-8859-5";
      };
      if (v instanceof Iso_8859_6) {
          return "iso-8859-6";
      };
      if (v instanceof Iso_8859_7) {
          return "iso-8859-7";
      };
      if (v instanceof Iso_8859_8) {
          return "iso-8859-8";
      };
      if (v instanceof Iso_8859_8_I) {
          return "iso-8859-8-i";
      };
      if (v instanceof Iso_8859_10) {
          return "iso-8859-10";
      };
      if (v instanceof Iso_8859_13) {
          return "iso-8859-13";
      };
      if (v instanceof Iso_8859_14) {
          return "iso-8859-14";
      };
      if (v instanceof Iso_8859_15) {
          return "iso-8859-15";
      };
      if (v instanceof Iso_8859_16) {
          return "iso-8859-16";
      };
      if (v instanceof Koi8_R) {
          return "koi8-r";
      };
      if (v instanceof Koi8_U) {
          return "koi8-u";
      };
      if (v instanceof Macintosh) {
          return "macintosh";
      };
      if (v instanceof Windows_874) {
          return "windows-874";
      };
      if (v instanceof Windows_1250) {
          return "windows-1250";
      };
      if (v instanceof Windows_1251) {
          return "windows-1251";
      };
      if (v instanceof Windows_1252) {
          return "windows-1252";
      };
      if (v instanceof Windows_1253) {
          return "windows-1253";
      };
      if (v instanceof Windows_1254) {
          return "windows-1254";
      };
      if (v instanceof Windows_1255) {
          return "windows-1255";
      };
      if (v instanceof Windows_1256) {
          return "windows-1256";
      };
      if (v instanceof Windows_1257) {
          return "windows-1257";
      };
      if (v instanceof Windows_1258) {
          return "windows-1258";
      };
      if (v instanceof X_Mac_Cyrillic) {
          return "x-max-cyrillic";
      };
      if (v instanceof Gbk) {
          return "gbk";
      };
      if (v instanceof Gb18030) {
          return "gb18030";
      };
      if (v instanceof Big5) {
          return "big5";
      };
      if (v instanceof Euc_Jp) {
          return "euc-jp";
      };
      if (v instanceof Iso_2022_Jp) {
          return "iso-2022-jp";
      };
      if (v instanceof Shift_Jis) {
          return "shift-jis";
      };
      if (v instanceof Euc_Kr) {
          return "euc-kr";
      };
      if (v instanceof Replacement) {
          return "iso-2022-kr";
      };
      if (v instanceof Utf_16Be) {
          return "utf-16be";
      };
      if (v instanceof Utf_16Le) {
          return "utf-16le";
      };
      if (v instanceof X_User_Defined) {
          return "x-user-defined";
      };
      throw new Error("Failed pattern match at Data.TextDecoder (line 87, column 1 - line 127, column 41): " + [ v.constructor.name ]);
  });
  var decode = function (encoding) {
      return function (buffer) {
          return $foreign.decodeImpl(Data_Either.Left.create, Data_Either.Right.create, Data_Show.show(showEncoding)(encoding), buffer);
      };
  };
  var decodeUtf8 = decode(Utf8.value);
  exports["decodeUtf8"] = decodeUtf8;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.Base64"] = $PS["Data.String.Base64"] || {};
  var exports = $PS["Data.String.Base64"];
  var $foreign = $PS["Data.String.Base64"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_String_Base64_Internal = $PS["Data.String.Base64.Internal"];
  var Data_TextDecoder = $PS["Data.TextDecoder"];
  var atob = function (str) {
      return $foreign.atobImpl(Data_Either.Left.create, Data_Either.Right.create, str);
  };
  var decode = function (str) {
      if (Data_String_Base64_Internal.atobIsDefined) {
          return Control_Bind.bind(Data_Either.bindEither)(Data_Functor.map(Data_Either.functorEither)(Data_String_Base64_Internal.unsafeStringToUint8ArrayOfCharCodes)(atob(Data_String_Base64_Internal.toRfc4648(str))))(Data_TextDecoder.decodeUtf8);
      };
      return $foreign.decodeNodeImpl(Data_Either.Left.create, Data_Either.Right.create, Data_String_Base64_Internal.toRfc4648(str));
  };
  exports["decode"] = decode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.CaseInsensitive"] = $PS["Data.String.CaseInsensitive"] || {};
  var exports = $PS["Data.String.CaseInsensitive"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_String_Common = $PS["Data.String.Common"];                
  var CaseInsensitiveString = function (x) {
      return x;
  }; 
  var newtypeCaseInsensitiveString = new Data_Newtype.Newtype(function (n) {
      return n;
  }, CaseInsensitiveString);
  var eqCaseInsensitiveString = new Data_Eq.Eq(function (v) {
      return function (v1) {
          return Data_String_Common.toLower(v) === Data_String_Common.toLower(v1);
      };
  });
  var ordCaseInsensitiveString = new Data_Ord.Ord(function () {
      return eqCaseInsensitiveString;
  }, function (v) {
      return function (v1) {
          return Data_Ord.compare(Data_Ord.ordString)(Data_String_Common.toLower(v))(Data_String_Common.toLower(v1));
      };
  });
  exports["ordCaseInsensitiveString"] = ordCaseInsensitiveString;
  exports["newtypeCaseInsensitiveString"] = newtypeCaseInsensitiveString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.NonEmpty.Internal"] = $PS["Data.String.NonEmpty.Internal"] || {};
  var exports = $PS["Data.String.NonEmpty.Internal"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];          
  var NonEmptyString = function (x) {
      return x;
  };
  var toString = function (v) {
      return v;
  }; 
  var semigroupNonEmptyString = Data_Semigroup.semigroupString;
  var joinWith = function (dictFoldable) {
      return function (splice) {
          var $48 = Data_Foldable.intercalate(dictFoldable)(Data_Monoid.monoidString)(splice);
          return function ($49) {
              return $48($49);
          };
      };
  };
  var join1With = function (dictFoldable1) {
      return function (splice) {
          var $50 = joinWith(dictFoldable1.Foldable0())(splice);
          return function ($51) {
              return NonEmptyString($50($51));
          };
      };
  };
  var fromString = function (v) {
      if (v === "") {
          return Data_Maybe.Nothing.value;
      };
      return new Data_Maybe.Just(v);
  };
  var unsafeFromString = function (dictPartial) {
      var $52 = Data_Maybe.fromJust();
      return function ($53) {
          return $52(fromString($53));
      };
  };
  var appendString = function (v) {
      return function (s2) {
          return v + s2;
      };
  };
  exports["fromString"] = fromString;
  exports["unsafeFromString"] = unsafeFromString;
  exports["toString"] = toString;
  exports["appendString"] = appendString;
  exports["joinWith"] = joinWith;
  exports["join1With"] = join1With;
  exports["semigroupNonEmptyString"] = semigroupNonEmptyString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.NonEmpty.CodeUnits"] = $PS["Data.String.NonEmpty.CodeUnits"] || {};
  var exports = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Unsafe_Coerce = $PS["Unsafe.Coerce"];                
  var toNonEmptyString = Unsafe_Coerce.unsafeCoerce;
  var singleton = function ($13) {
      return toNonEmptyString(Data_String_CodeUnits.singleton($13));
  };
  var liftS = Unsafe_Coerce.unsafeCoerce;
  var indexOf = function ($21) {
      return liftS(Data_String_CodeUnits.indexOf($21));
  };
  var fromNonEmptyString = Unsafe_Coerce.unsafeCoerce;
  var length = function ($22) {
      return Data_String_CodeUnits.length(fromNonEmptyString($22));
  };
  var splitAt = function (i) {
      return function (nes) {
          var v = Data_String_CodeUnits.splitAt(i)(fromNonEmptyString(nes));
          return {
              before: Data_String_NonEmpty_Internal.fromString(v.before),
              after: Data_String_NonEmpty_Internal.fromString(v.after)
          };
      };
  };
  var drop = function (i) {
      return function (nes) {
          var s = fromNonEmptyString(nes);
          var $12 = i >= Data_String_CodeUnits.length(s);
          if ($12) {
              return Data_Maybe.Nothing.value;
          };
          return new Data_Maybe.Just(toNonEmptyString(Data_String_CodeUnits.drop(i)(s)));
      };
  };
  exports["singleton"] = singleton;
  exports["indexOf"] = indexOf;
  exports["drop"] = drop;
  exports["splitAt"] = splitAt;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.String.Pattern"] = $PS["Data.String.Pattern"] || {};
  var exports = $PS["Data.String.Pattern"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Pattern = function (x) {
      return x;
  };              
  var newtypePattern = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Pattern);
  exports["Pattern"] = Pattern;
  exports["newtypePattern"] = newtypePattern;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Data.These"] = $PS["Data.These"] || {};
  var exports = $PS["Data.These"];
  var Data_Maybe = $PS["Data.Maybe"];                
  var This = (function () {
      function This(value0) {
          this.value0 = value0;
      };
      This.create = function (value0) {
          return new This(value0);
      };
      return This;
  })();
  var That = (function () {
      function That(value0) {
          this.value0 = value0;
      };
      That.create = function (value0) {
          return new That(value0);
      };
      return That;
  })();
  var Both = (function () {
      function Both(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Both.create = function (value0) {
          return function (value1) {
              return new Both(value0, value1);
          };
      };
      return Both;
  })();
  var theseRight = function (v) {
      if (v instanceof Both) {
          return new Data_Maybe.Just(v.value1);
      };
      if (v instanceof That) {
          return new Data_Maybe.Just(v.value0);
      };
      return Data_Maybe.Nothing.value;
  };
  var theseLeft = function (v) {
      if (v instanceof Both) {
          return new Data_Maybe.Just(v.value0);
      };
      if (v instanceof This) {
          return new Data_Maybe.Just(v.value0);
      };
      return Data_Maybe.Nothing.value;
  };
  exports["This"] = This;
  exports["That"] = That;
  exports["Both"] = Both;
  exports["theseLeft"] = theseLeft;
  exports["theseRight"] = theseRight;
})(PS);
(function(exports) {
  /* global exports, require */
  /* jshint -W097 */

  'use strict';
  var pg =require("pg"); 

  // pg does strange thing converting DATE
  // value to js Date, so we have
  // to prevent this craziness
  pg.types.setTypeParser(1082 /* DATE_OID */, function(dateString) { return dateString; });

  exports.ffiNewPool = function(config) {
      return function() {
          return new pg.Pool(config);
      };
  };

  exports.ffiConnect = function (config) {
      return function (pool) {
          return function (onError, onSuccess) {
              var p = pool.connect().then(function(client) {
                  onSuccess(config.right({
                      connection: client,
                      done: function() {
                          return client.release();
                      }
                  }));
              }).catch(function(err) {
                  var pgError = config.nullableLeft(err);
                  if (pgError) {
                      onSuccess(pgError);
                  } else {
                      onError(err);
                  }
              });

              return function (cancelError, cancelerError, cancelerSuccess) {
                  p.cancel();
                  cancelerSuccess();
              };
          };
      };
  };

  exports.ffiUnsafeQuery = function(config) {
      return function(client) {
          return function(sql) {
              return function(values) {
                  return function(onError, onSuccess) {
                      var q = client.query({
                          text: sql,
                          values: values,
                          rowMode: 'array',
                      }).then(function(result) {
                          onSuccess(config.right(result));
                      }).catch(function(err) {
                          var pgError = config.nullableLeft(err);
                          if (pgError) {
                              onSuccess(pgError);
                          } else {
                              onError(err);
                          }
                      });

                      return function (cancelError, cancelerError, cancelerSuccess) {
                          q.cancel();
                          cancelerSuccess();
                      };
                  };
              };
          };
      };
  };

  exports.ffiSQLState = function (error) {
      return error.code || null;
  };

  exports.ffiErrorDetail = function (error) {
      return {
          severity: error.severity || '',
          code: error.code || '',
          message: error.message || '',
          detail: error.detail || '',
          hint: error.hint || '',
          position: error.position || '',
          internalPosition: error.internalPosition || '',
          internalQuery: error.internalQuery || '',
          where_: error.where || '',
          schema: error.schema || '',
          table: error.table || '',
          column: error.column || '',
          dataType: error.dataType || '',
          constraint: error.constraint || '',
          file: error.file || '',
          line: error.line || '',
          routine: error.routine || ''
      };
  };
})(PS["Database.PostgreSQL"] = PS["Database.PostgreSQL"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Database.PostgreSQL.Value"] = $PS["Database.PostgreSQL.Value"] || {};
  var exports = $PS["Database.PostgreSQL.Value"];
  var Control_Monad_Except = $PS["Control.Monad.Except"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Show = $PS["Data.Show"];
  var Foreign = $PS["Foreign"];                              
  var ToSQLValue = function (toSQLValue) {
      this.toSQLValue = toSQLValue;
  };
  var FromSQLValue = function (fromSQLValue) {
      this.fromSQLValue = fromSQLValue;
  };
  var toSQLValueString = new ToSQLValue(Foreign.unsafeToForeign);
  var toSQLValueInt = new ToSQLValue(Foreign.unsafeToForeign);    
  var toSQLValue = function (dict) {
      return dict.toSQLValue;
  }; 
  var fromSQLValueInt = new FromSQLValue((function () {
      var $41 = Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Data_List_Types.showNonEmptyList(Foreign.showForeignError)));
      return function ($42) {
          return $41(Control_Monad_Except.runExcept(Foreign.readInt($42)));
      };
  })());
  var fromSQLValue = function (dict) {
      return dict.fromSQLValue;
  };
  exports["fromSQLValue"] = fromSQLValue;
  exports["toSQLValue"] = toSQLValue;
  exports["fromSQLValueInt"] = fromSQLValueInt;
  exports["toSQLValueInt"] = toSQLValueInt;
  exports["toSQLValueString"] = toSQLValueString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Database.PostgreSQL.Row"] = $PS["Database.PostgreSQL.Row"] || {};
  var exports = $PS["Database.PostgreSQL.Row"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Array = $PS["Data.Array"];
  var Data_Either = $PS["Data.Either"];
  var Data_Show = $PS["Data.Show"];
  var Database_PostgreSQL_Value = $PS["Database.PostgreSQL.Value"];
  var Row3 = (function () {
      function Row3(value0, value1, value2) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
      };
      Row3.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return new Row3(value0, value1, value2);
              };
          };
      };
      return Row3;
  })();
  var Row1 = (function () {
      function Row1(value0) {
          this.value0 = value0;
      };
      Row1.create = function (value0) {
          return new Row1(value0);
      };
      return Row1;
  })();
  var Row0 = (function () {
      function Row0() {

      };
      Row0.value = new Row0();
      return Row0;
  })();
  var ToSQLRow = function (toSQLRow) {
      this.toSQLRow = toSQLRow;
  };
  var FromSQLRow = function (fromSQLRow) {
      this.fromSQLRow = fromSQLRow;
  };
  var toSQLRowRow3 = function (dictToSQLValue) {
      return function (dictToSQLValue1) {
          return function (dictToSQLValue2) {
              return new ToSQLRow(function (v) {
                  return [ Database_PostgreSQL_Value.toSQLValue(dictToSQLValue)(v.value0), Database_PostgreSQL_Value.toSQLValue(dictToSQLValue1)(v.value1), Database_PostgreSQL_Value.toSQLValue(dictToSQLValue2)(v.value2) ];
              });
          };
      };
  };
  var toSQLRowRow0 = new ToSQLRow(function (v) {
      return [  ];
  });                                                                                             
  var toSQLRow = function (dict) {
      return dict.toSQLRow;
  };
  var fromSQLRowRow1 = function (dictFromSQLValue) {
      return new FromSQLRow(function (v) {
          if (v.length === 1) {
              return Control_Apply.apply(Data_Either.applyEither)(Control_Applicative.pure(Data_Either.applicativeEither)(Row1.create))(Database_PostgreSQL_Value.fromSQLValue(dictFromSQLValue)(v[0]));
          };
          var n = Data_Array.length(v);
          return Data_Either.Left.create("Row has " + (Data_Show.show(Data_Show.showInt)(n) + " fields, expecting 1."));
      });
  }; 
  var fromSQLRow = function (dict) {
      return dict.fromSQLRow;
  };
  exports["fromSQLRow"] = fromSQLRow;
  exports["toSQLRow"] = toSQLRow;
  exports["Row0"] = Row0;
  exports["Row3"] = Row3;
  exports["toSQLRowRow0"] = toSQLRowRow0;
  exports["fromSQLRowRow1"] = fromSQLRowRow1;
  exports["toSQLRowRow3"] = toSQLRowRow3;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Database.PostgreSQL"] = $PS["Database.PostgreSQL"] || {};
  var exports = $PS["Database.PostgreSQL"];
  var $foreign = $PS["Database.PostgreSQL"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Generic_Rep = $PS["Data.Generic.Rep"];
  var Data_Generic_Rep_Show = $PS["Data.Generic.Rep.Show"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Nullable = $PS["Data.Nullable"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_CodePoints = $PS["Data.String.CodePoints"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Data_Traversable = $PS["Data.Traversable"];
  var Data_Unit = $PS["Data.Unit"];
  var Database_PostgreSQL_Row = $PS["Database.PostgreSQL.Row"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Compat = $PS["Effect.Aff.Compat"];
  var Effect_Class = $PS["Effect.Class"];
  var ConnectionError = (function () {
      function ConnectionError(value0) {
          this.value0 = value0;
      };
      ConnectionError.create = function (value0) {
          return new ConnectionError(value0);
      };
      return ConnectionError;
  })();
  var ConversionError = (function () {
      function ConversionError(value0) {
          this.value0 = value0;
      };
      ConversionError.create = function (value0) {
          return new ConversionError(value0);
      };
      return ConversionError;
  })();
  var InternalError = (function () {
      function InternalError(value0) {
          this.value0 = value0;
      };
      InternalError.create = function (value0) {
          return new InternalError(value0);
      };
      return InternalError;
  })();
  var OperationalError = (function () {
      function OperationalError(value0) {
          this.value0 = value0;
      };
      OperationalError.create = function (value0) {
          return new OperationalError(value0);
      };
      return OperationalError;
  })();
  var ProgrammingError = (function () {
      function ProgrammingError(value0) {
          this.value0 = value0;
      };
      ProgrammingError.create = function (value0) {
          return new ProgrammingError(value0);
      };
      return ProgrammingError;
  })();
  var IntegrityError = (function () {
      function IntegrityError(value0) {
          this.value0 = value0;
      };
      IntegrityError.create = function (value0) {
          return new IntegrityError(value0);
      };
      return IntegrityError;
  })();
  var DataError = (function () {
      function DataError(value0) {
          this.value0 = value0;
      };
      DataError.create = function (value0) {
          return new DataError(value0);
      };
      return DataError;
  })();
  var NotSupportedError = (function () {
      function NotSupportedError(value0) {
          this.value0 = value0;
      };
      NotSupportedError.create = function (value0) {
          return new NotSupportedError(value0);
      };
      return NotSupportedError;
  })();
  var QueryCanceledError = (function () {
      function QueryCanceledError(value0) {
          this.value0 = value0;
      };
      QueryCanceledError.create = function (value0) {
          return new QueryCanceledError(value0);
      };
      return QueryCanceledError;
  })();
  var TransactionRollbackError = (function () {
      function TransactionRollbackError(value0) {
          this.value0 = value0;
      };
      TransactionRollbackError.create = function (value0) {
          return new TransactionRollbackError(value0);
      };
      return TransactionRollbackError;
  })();     
  var newPool = function (cfg) {
      var cfg$prime = {
          user: Data_Nullable.toNullable(cfg.user),
          password: Data_Nullable.toNullable(cfg.password),
          host: Data_Nullable.toNullable(cfg.host),
          port: Data_Nullable.toNullable(cfg.port),
          database: cfg.database,
          max: Data_Nullable.toNullable(cfg.max),
          idleTimeoutMillis: Data_Nullable.toNullable(cfg.idleTimeoutMillis)
      };
      return $foreign.ffiNewPool(cfg$prime);
  };
  var genericPGError = new Data_Generic_Rep.Generic(function (x) {
      if (x instanceof ConnectionError) {
          return new Data_Generic_Rep.Inl(x.value0);
      };
      if (x instanceof ConversionError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0));
      };
      if (x instanceof InternalError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0)));
      };
      if (x instanceof OperationalError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0))));
      };
      if (x instanceof ProgrammingError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0)))));
      };
      if (x instanceof IntegrityError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0))))));
      };
      if (x instanceof DataError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0)))))));
      };
      if (x instanceof NotSupportedError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0))))))));
      };
      if (x instanceof QueryCanceledError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inl(x.value0)))))))));
      };
      if (x instanceof TransactionRollbackError) {
          return new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(new Data_Generic_Rep.Inr(x.value0)))))))));
      };
      throw new Error("Failed pattern match at Database.PostgreSQL (line 265, column 1 - line 265, column 52): " + [ x.constructor.name ]);
  }, function (x) {
      if (x instanceof Data_Generic_Rep.Inl) {
          return new ConnectionError(x.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && x.value0 instanceof Data_Generic_Rep.Inl) {
          return new ConversionError(x.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0 instanceof Data_Generic_Rep.Inl)) {
          return new InternalError(x.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0 instanceof Data_Generic_Rep.Inl))) {
          return new OperationalError(x.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inl)))) {
          return new ProgrammingError(x.value0.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inl))))) {
          return new IntegrityError(x.value0.value0.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inl)))))) {
          return new DataError(x.value0.value0.value0.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inl))))))) {
          return new NotSupportedError(x.value0.value0.value0.value0.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inl)))))))) {
          return new QueryCanceledError(x.value0.value0.value0.value0.value0.value0.value0.value0.value0);
      };
      if (x instanceof Data_Generic_Rep.Inr && (x.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && (x.value0.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr && x.value0.value0.value0.value0.value0.value0.value0.value0 instanceof Data_Generic_Rep.Inr)))))))) {
          return new TransactionRollbackError(x.value0.value0.value0.value0.value0.value0.value0.value0.value0);
      };
      throw new Error("Failed pattern match at Database.PostgreSQL (line 265, column 1 - line 265, column 52): " + [ x.constructor.name ]);
  });
  var showPGError = new Data_Show.Show(Data_Generic_Rep_Show.genericShow(genericPGError)(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showString))(new Data_Symbol.IsSymbol(function () {
      return "ConnectionError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showString))(new Data_Symbol.IsSymbol(function () {
      return "ConversionError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "InternalError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "OperationalError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "ProgrammingError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "IntegrityError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "DataError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "NotSupportedError";
  })))(Data_Generic_Rep_Show.genericShowSum(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "QueryCanceledError";
  })))(Data_Generic_Rep_Show.genericShowConstructor(Data_Generic_Rep_Show.genericShowArgsArgument(Data_Show.showRecord()(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "code";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "column";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "constraint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "dataType";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "detail";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "file";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "hint";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalPosition";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "internalQuery";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "line";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "message";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "position";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "routine";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "schema";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "severity";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "table";
  }))(Data_Show.showRecordFieldsCons(new Data_Symbol.IsSymbol(function () {
      return "where_";
  }))(Data_Show.showRecordFieldsNil)(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))(Data_Show.showString))))(new Data_Symbol.IsSymbol(function () {
      return "TransactionRollbackError";
  })))))))))))));
  var convertError = function (err) {
      var prefix = function (p) {
          var $185 = Data_Maybe.maybe(false)(function (v) {
              return v === 0;
          });
          var $186 = Data_String_CodePoints.indexOf(p);
          return function ($187) {
              return $185($186($187));
          };
      };
      var convert = function (s) {
          var $142 = prefix("0A")(s);
          if ($142) {
              return NotSupportedError.create;
          };
          var $143 = prefix("20")(s) || prefix("21")(s);
          if ($143) {
              return ProgrammingError.create;
          };
          var $144 = prefix("22")(s);
          if ($144) {
              return DataError.create;
          };
          var $145 = prefix("23")(s);
          if ($145) {
              return IntegrityError.create;
          };
          var $146 = prefix("24")(s) || prefix("25")(s);
          if ($146) {
              return InternalError.create;
          };
          var $147 = prefix("26")(s) || (prefix("27")(s) || prefix("28")(s));
          if ($147) {
              return OperationalError.create;
          };
          var $148 = prefix("2B")(s) || (prefix("2D")(s) || prefix("2F")(s));
          if ($148) {
              return InternalError.create;
          };
          var $149 = prefix("34")(s);
          if ($149) {
              return OperationalError.create;
          };
          var $150 = prefix("38")(s) || (prefix("39")(s) || prefix("3B")(s));
          if ($150) {
              return InternalError.create;
          };
          var $151 = prefix("3D")(s) || prefix("3F")(s);
          if ($151) {
              return ProgrammingError.create;
          };
          var $152 = prefix("40")(s);
          if ($152) {
              return TransactionRollbackError.create;
          };
          var $153 = prefix("42")(s) || prefix("44")(s);
          if ($153) {
              return ProgrammingError.create;
          };
          var $154 = s === "57014";
          if ($154) {
              return QueryCanceledError.create;
          };
          var $155 = prefix("5")(s);
          if ($155) {
              return OperationalError.create;
          };
          var $156 = prefix("F")(s);
          if ($156) {
              return InternalError.create;
          };
          var $157 = prefix("H")(s);
          if ($157) {
              return OperationalError.create;
          };
          var $158 = prefix("P")(s);
          if ($158) {
              return InternalError.create;
          };
          var $159 = prefix("X")(s);
          if ($159) {
              return InternalError.create;
          };
          return Data_Function["const"](new ConnectionError(s));
      };
      var v = Data_Nullable.toMaybe($foreign.ffiSQLState(err));
      if (v instanceof Data_Maybe.Nothing) {
          return Data_Maybe.Nothing.value;
      };
      if (v instanceof Data_Maybe.Just) {
          return Data_Maybe.Just.create(convert(v.value0)($foreign.ffiErrorDetail(err)));
      };
      throw new Error("Failed pattern match at Database.PostgreSQL (line 295, column 5 - line 297, column 70): " + [ v.constructor.name ]);
  };
  var unsafeQuery = function (c) {
      return function (s) {
          var p = {
              nullableLeft: (function () {
                  var $188 = Data_Functor.map(Data_Maybe.functorMaybe)(Data_Either.Left.create);
                  return function ($189) {
                      return Data_Nullable.toNullable($188(convertError($189)));
                  };
              })(),
              right: Data_Either.Right.create
          };
          var $190 = $foreign.ffiUnsafeQuery(p)(c)(s);
          return function ($191) {
              return Effect_Aff_Compat.fromEffectFnAff($190($191));
          };
      };
  };
  var execute = function (dictToSQLRow) {
      return function (conn) {
          return function (v) {
              return function (values) {
                  return Data_Functor.map(Effect_Aff.functorAff)((function () {
                      var $192 = Data_Either.either(Data_Either.Right.create)(Data_Either.Left.create);
                      return function ($193) {
                          return Data_Either.hush($192($193));
                      };
                  })())(unsafeQuery(conn)(v)(Database_PostgreSQL_Row.toSQLRow(dictToSQLRow)(values)));
              };
          };
      };
  };
  var withTransaction = function (conn) {
      return function (action) {
          var rollback = execute(Database_PostgreSQL_Row.toSQLRowRow0)(conn)("ROLLBACK TRANSACTION")(Database_PostgreSQL_Row.Row0.value);
          var commit = execute(Database_PostgreSQL_Row.toSQLRowRow0)(conn)("COMMIT TRANSACTION")(Database_PostgreSQL_Row.Row0.value);
          var begin = execute(Database_PostgreSQL_Row.toSQLRowRow0)(conn)("BEGIN TRANSACTION")(Database_PostgreSQL_Row.Row0.value);
          return Control_Bind.bind(Effect_Aff.bindAff)(begin)(function (v) {
              if (v instanceof Data_Maybe.Nothing) {
                  return Control_Bind.bind(Effect_Aff.bindAff)(Control_Monad_Error_Class.catchError(Effect_Aff.monadErrorAff)(action)(function (jsErr) {
                      return Control_Bind.discard(Control_Bind.discardUnit)(Effect_Aff.bindAff)(Data_Functor["void"](Effect_Aff.functorAff)(rollback))(function () {
                          return Control_Monad_Error_Class.throwError(Effect_Aff.monadThrowAff)(jsErr);
                      });
                  }))(function (a) {
                      return Control_Bind.bind(Effect_Aff.bindAff)(commit)(function (v1) {
                          if (v1 instanceof Data_Maybe.Just) {
                              return Control_Applicative.pure(Effect_Aff.applicativeAff)(new Data_Either.Left(v1.value0));
                          };
                          if (v1 instanceof Data_Maybe.Nothing) {
                              return Control_Applicative.pure(Effect_Aff.applicativeAff)(new Data_Either.Right(a));
                          };
                          throw new Error("Failed pattern match at Database.PostgreSQL (line 166, column 20 - line 168, column 35): " + [ v1.constructor.name ]);
                      });
                  });
              };
              if (v instanceof Data_Maybe.Just) {
                  return Control_Applicative.pure(Effect_Aff.applicativeAff)(new Data_Either.Left(v.value0));
              };
              throw new Error("Failed pattern match at Database.PostgreSQL (line 161, column 15 - line 169, column 41): " + [ v.constructor.name ]);
          });
      };
  };
  var query = function (dictToSQLRow) {
      return function (dictFromSQLRow) {
          return function (conn) {
              return function (v) {
                  return function (values) {
                      return Control_Bind.bind(Effect_Aff.bindAff)(unsafeQuery(conn)(v)(Database_PostgreSQL_Row.toSQLRow(dictToSQLRow)(values)))(function (r) {
                          return Control_Applicative.pure(Effect_Aff.applicativeAff)(Control_Bind.bind(Data_Either.bindEither)(r)((function () {
                              var $194 = Data_Traversable.traverse(Data_Traversable.traversableArray)(Data_Either.applicativeEither)((function () {
                                  var $196 = Data_Bifunctor.lmap(Data_Either.bifunctorEither)(ConversionError.create);
                                  var $197 = Database_PostgreSQL_Row.fromSQLRow(dictFromSQLRow);
                                  return function ($198) {
                                      return $196($197($198));
                                  };
                              })());
                              return function ($195) {
                                  return $194((function (v1) {
                                      return v1.rows;
                                  })($195));
                              };
                          })()));
                      });
                  };
              };
          };
      };
  };
  var connect = (function () {
      var $201 = $foreign.ffiConnect({
          nullableLeft: (function () {
              var $203 = Data_Functor.map(Data_Maybe.functorMaybe)(Data_Either.Left.create);
              return function ($204) {
                  return Data_Nullable.toNullable($203(convertError($204)));
              };
          })(),
          right: Data_Either.Right.create
      });
      return function ($202) {
          return Effect_Aff_Compat.fromEffectFnAff($201($202));
      };
  })();
  var withConnection = function (p) {
      return function (k) {
          var run = function (v) {
              if (v instanceof Data_Either.Left) {
                  return k(new Data_Either.Left(v.value0));
              };
              if (v instanceof Data_Either.Right) {
                  return k(new Data_Either.Right(v.value0.connection));
              };
              throw new Error("Failed pattern match at Database.PostgreSQL (line 124, column 5 - line 124, column 34): " + [ v.constructor.name ]);
          };
          var cleanup = function (v) {
              if (v instanceof Data_Either.Left) {
                  return Control_Applicative.pure(Effect_Aff.applicativeAff)(Data_Unit.unit);
              };
              if (v instanceof Data_Either.Right) {
                  return Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(v.value0.done);
              };
              throw new Error("Failed pattern match at Database.PostgreSQL (line 121, column 5 - line 121, column 33): " + [ v.constructor.name ]);
          };
          return Effect_Aff.bracket(connect(p))(cleanup)(run);
      };
  };
  exports["newPool"] = newPool;
  exports["withConnection"] = withConnection;
  exports["withTransaction"] = withTransaction;
  exports["execute"] = execute;
  exports["query"] = query;
  exports["showPGError"] = showPGError;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Aff.Class"] = $PS["Effect.Aff.Class"] || {};
  var exports = $PS["Effect.Aff.Class"];
  var Control_Category = $PS["Control.Category"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Control_Monad_Trans_Class = $PS["Control.Monad.Trans.Class"];
  var Effect_Aff = $PS["Effect.Aff"];                
  var MonadAff = function (MonadEffect0, liftAff) {
      this.MonadEffect0 = MonadEffect0;
      this.liftAff = liftAff;
  };
  var monadAffAff = new MonadAff(function () {
      return Effect_Aff.monadEffectAff;
  }, Control_Category.identity(Control_Category.categoryFn));
  var liftAff = function (dict) {
      return dict.liftAff;
  };
  var monadAffExceptT = function (dictMonadAff) {
      return new MonadAff(function () {
          return Control_Monad_Except_Trans.monadEffectExceptT(dictMonadAff.MonadEffect0());
      }, (function () {
          var $13 = Control_Monad_Trans_Class.lift(Control_Monad_Except_Trans.monadTransExceptT)((dictMonadAff.MonadEffect0()).Monad0());
          var $14 = liftAff(dictMonadAff);
          return function ($15) {
              return $13($14($15));
          };
      })());
  };
  exports["liftAff"] = liftAff;
  exports["monadAffAff"] = monadAffAff;
  exports["monadAffExceptT"] = monadAffExceptT;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Database.PostgreSQL.PG"] = $PS["Database.PostgreSQL.PG"] || {};
  var exports = $PS["Database.PostgreSQL.PG"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Data_Either = $PS["Data.Either"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Unit = $PS["Data.Unit"];
  var Database_PostgreSQL = $PS["Database.PostgreSQL"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];                
  var withTransaction = function (dictMonadAff) {
      return function (dictMonadError) {
          return function (f) {
              return function (conn) {
                  return function (action) {
                      return Control_Bind.bind(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Aff_Class.liftAff(dictMonadAff)(Database_PostgreSQL.withTransaction(conn)(f(action))))(function (res) {
                          return Data_Either.either(Control_Monad_Error_Class.throwError(dictMonadError.MonadThrow0()))(Control_Applicative.pure(((dictMonadAff.MonadEffect0()).Monad0()).Applicative0()))(Control_Bind.join(Data_Either.bindEither)(res));
                      });
                  };
              };
          };
      };
  };
  var withConnection = function (dictMonadError) {
      return function (dictMonadAff) {
          return function (f) {
              return function (p) {
                  return function (k) {
                      return Control_Bind.bind(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Aff_Class.liftAff(dictMonadAff)(Database_PostgreSQL.withConnection(p)(function (v) {
                          if (v instanceof Data_Either.Right) {
                              return f(k(v.value0));
                          };
                          if (v instanceof Data_Either.Left) {
                              return Control_Applicative.pure(Effect_Aff.applicativeAff)(new Data_Either.Left(v.value0));
                          };
                          throw new Error("Failed pattern match at Database.PostgreSQL.PG (line 45, column 39 - line 47, column 36): " + [ v.constructor.name ]);
                      })))(function (res) {
                          return Data_Either.either(Control_Monad_Error_Class.throwError(dictMonadError.MonadThrow0()))(Control_Applicative.pure(((dictMonadAff.MonadEffect0()).Monad0()).Applicative0()))(res);
                      });
                  };
              };
          };
      };
  };
  var hoistAffEither = function (dictMonadAff) {
      return function (dictMonadError) {
          return function (m) {
              return Control_Bind.bind(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Aff_Class.liftAff(dictMonadAff)(m))(Data_Either.either(Control_Monad_Error_Class.throwError(dictMonadError.MonadThrow0()))(Control_Applicative.pure(((dictMonadAff.MonadEffect0()).Monad0()).Applicative0())));
          };
      };
  };
  var query = function (dictToSQLRow) {
      return function (dictFromSQLRow) {
          return function (dictMonadError) {
              return function (dictMonadAff) {
                  return function (conn) {
                      return function (sql) {
                          var $27 = hoistAffEither(dictMonadAff)(dictMonadError);
                          var $28 = Database_PostgreSQL.query(dictToSQLRow)(dictFromSQLRow)(conn)(sql);
                          return function ($29) {
                              return $27($28($29));
                          };
                      };
                  };
              };
          };
      };
  };
  var execute = function (dictToSQLRow) {
      return function (dictMonadError) {
          return function (dictMonadAff) {
              return function (conn) {
                  return function (sql) {
                      return function (values) {
                          return Control_Bind.bind(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Aff_Class.liftAff(dictMonadAff)(Database_PostgreSQL.execute(dictToSQLRow)(conn)(sql)(values)))(function (err) {
                              return Data_Maybe.maybe(Control_Applicative.pure(((dictMonadAff.MonadEffect0()).Monad0()).Applicative0())(Data_Unit.unit))(Control_Monad_Error_Class.throwError(dictMonadError.MonadThrow0()))(err);
                          });
                      };
                  };
              };
          };
      };
  };
  exports["execute"] = execute;
  exports["query"] = query;
  exports["withConnection"] = withConnection;
  exports["withTransaction"] = withTransaction;
})(PS);
(function(exports) {
  "use strict";

  exports.log = function (s) {
    return function () {
      console.log(s);
      return {};
    };
  };

  exports.error = function (s) {
    return function () {
      console.error(s);
      return {};
    };
  };
})(PS["Effect.Console"] = PS["Effect.Console"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Console"] = $PS["Effect.Console"] || {};
  var exports = $PS["Effect.Console"];
  var $foreign = $PS["Effect.Console"];
  exports["log"] = $foreign.log;
  exports["error"] = $foreign.error;
})(PS);
(function(exports) {
  "use strict";

  exports.new = function (val) {
    return function () {
      return { value: val };
    };
  };

  exports.read = function (ref) {
    return function () {
      return ref.value;
    };
  };

  exports["modify'"] = function (f) {
    return function (ref) {
      return function () {
        var t = f(ref.value);
        ref.value = t.state;
        return t.value;
      };
    };
  };
})(PS["Effect.Ref"] = PS["Effect.Ref"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Effect.Ref"] = $PS["Effect.Ref"] || {};
  var exports = $PS["Effect.Ref"];
  var $foreign = $PS["Effect.Ref"];          
  var modify = function (f) {
      return $foreign["modify'"](function (s) {
          var s$prime = f(s);
          return {
              state: s$prime,
              value: s$prime
          };
      });
  };
  exports["modify"] = modify;
  exports["new"] = $foreign["new"];
  exports["read"] = $foreign.read;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Envisage.Logger"] = $PS["Envisage.Logger"] || {};
  var exports = $PS["Envisage.Logger"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Tuple = $PS["Data.Tuple"];                        
  var LoggerT = (function () {
      function LoggerT(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      LoggerT.create = function (value0) {
          return function (value1) {
              return new LoggerT(value0, value1);
          };
      };
      return LoggerT;
  })();
  var ReaderLoggerT = (function () {
      function ReaderLoggerT(value0) {
          this.value0 = value0;
      };
      ReaderLoggerT.create = function (value0) {
          return new ReaderLoggerT(value0);
      };
      return ReaderLoggerT;
  })();
  var runLoggerT = function (v) {
      return new Data_Tuple.Tuple(v.value0, v.value1);
  };
  var runReaderLoggerT = function (env) {
      return function (v) {
          return runLoggerT(v.value0(env));
      };
  };
  var readerLoggerT = ReaderLoggerT.create;
  var loggerT = LoggerT.create;                                                                                                                                                                                                                           
  var functorLogger = function (dictFunctor) {
      return new Data_Functor.Functor(function (f) {
          return function (v) {
              return new LoggerT(v.value0, Data_Functor.map(dictFunctor)(f)(v.value1));
          };
      });
  };
  var functorReaderLogger = function (dictFunctor) {
      return new Data_Functor.Functor(function (f) {
          return function (v) {
              return ReaderLoggerT.create(function (env) {
                  return Data_Functor.map(functorLogger(dictFunctor))(f)(v.value0(env));
              });
          };
      });
  };
  var applyLogger = function (dictSemigroup) {
      return function (dictApply) {
          return new Control_Apply.Apply(function () {
              return functorLogger(dictApply.Functor0());
          }, function (v) {
              return function (v1) {
                  return new LoggerT(Data_Semigroup.append(dictSemigroup)(v.value0)(v1.value0), Control_Apply.apply(dictApply)(v.value1)(v1.value1));
              };
          });
      };
  };
  var applyReaderLogger = function (dictSemigroup) {
      return function (dictApply) {
          return new Control_Apply.Apply(function () {
              return functorReaderLogger(dictApply.Functor0());
          }, function (v) {
              return function (v1) {
                  return ReaderLoggerT.create(function (env) {
                      return Control_Apply.apply(applyLogger(dictSemigroup)(dictApply))(v.value0(env))(v1.value0(env));
                  });
              };
          });
      };
  };
  var applicativeLogger = function (dictMonoid) {
      return function (dictApplicative) {
          return new Control_Applicative.Applicative(function () {
              return applyLogger(dictMonoid.Semigroup0())(dictApplicative.Apply0());
          }, function (x) {
              return LoggerT.create(Data_Monoid.mempty(dictMonoid))(Control_Applicative.pure(dictApplicative)(x));
          });
      };
  };
  var applicativeReaderLogger = function (dictMonoid) {
      return function (dictApplicative) {
          return new Control_Applicative.Applicative(function () {
              return applyReaderLogger(dictMonoid.Semigroup0())(dictApplicative.Apply0());
          }, function (x) {
              return ReaderLoggerT.create(Data_Function["const"](Control_Applicative.pure(applicativeLogger(dictMonoid)(dictApplicative))(x)));
          });
      };
  };
  exports["loggerT"] = loggerT;
  exports["runReaderLoggerT"] = runReaderLoggerT;
  exports["readerLoggerT"] = readerLoggerT;
  exports["functorReaderLogger"] = functorReaderLogger;
  exports["applyReaderLogger"] = applyReaderLogger;
  exports["applicativeReaderLogger"] = applicativeReaderLogger;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Type.Equality"] = $PS["Type.Equality"] || {};
  var exports = $PS["Type.Equality"];
  var TypeEquals = function (from, to) {
      this.from = from;
      this.to = to;
  };
  var to = function (dict) {
      return dict.to;
  };
  var refl = new TypeEquals(function (a) {
      return a;
  }, function (a) {
      return a;
  });
  exports["to"] = to;
  exports["refl"] = refl;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Envisage.Record"] = $PS["Envisage.Record"] || {};
  var exports = $PS["Envisage.Record"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Record = $PS["Record"];
  var Type_Data_RowList = $PS["Type.Data.RowList"];
  var Type_Equality = $PS["Type.Equality"];                
  var RecordUpdate = function (recordUpdate) {
      this.recordUpdate = recordUpdate;
  };
  var HasFunction = function (getFunction) {
      this.getFunction = getFunction;
  };
  var recordUpdateNil = function (dictApplicative) {
      return function (dictTypeEquals) {
          return new RecordUpdate(function (v) {
              return function (v1) {
                  return function (v2) {
                      return function (v3) {
                          return Control_Applicative.pure(dictApplicative)(Type_Equality.to(dictTypeEquals)({}));
                      };
                  };
              };
          });
      };
  };
  var recordUpdate = function (dict) {
      return dict.recordUpdate;
  };
  var getFunction = function (dict) {
      return dict.getFunction;
  };
  var recordUpdateCons = function (dictIsSymbol) {
      return function (dictLacks) {
          return function (dictLacks1) {
              return function (dictListToRow) {
                  return function (dictListToRow1) {
                      return function (dictCons) {
                          return function (dictCons1) {
                              return function (dictApplicative) {
                                  return function (dictApply) {
                                      return function (dictHasFunction) {
                                          return function (dictRecordUpdate) {
                                              return new RecordUpdate(function (v) {
                                                  return function (v1) {
                                                      return function (hf) {
                                                          return function (inputs) {
                                                              var v2 = Record.get(dictIsSymbol)()(Data_Symbol.SProxy.value)(inputs);
                                                              var v3 = getFunction(dictHasFunction)(hf)(v2);
                                                              var inputTail = Record["delete"](dictIsSymbol)()()(Data_Symbol.SProxy.value)(inputs);
                                                              var outputTail = recordUpdate(dictRecordUpdate)(Type_Data_RowList.RLProxy.value)(Type_Data_RowList.RLProxy.value)(hf)(inputTail);
                                                              return Control_Apply.apply(dictApplicative.Apply0())(Data_Functor.map((dictApplicative.Apply0()).Functor0())(Record.insert(dictIsSymbol)()()(Data_Symbol.SProxy.value))(v3))(outputTail);
                                                          };
                                                      };
                                                  };
                                              });
                                          };
                                      };
                                  };
                              };
                          };
                      };
                  };
              };
          };
      };
  };
  exports["recordUpdate"] = recordUpdate;
  exports["HasFunction"] = HasFunction;
  exports["recordUpdateNil"] = recordUpdateNil;
  exports["recordUpdateCons"] = recordUpdateCons;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Envisage.Internal"] = $PS["Envisage.Internal"] || {};
  var exports = $PS["Envisage.Internal"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];
  var Envisage_Logger = $PS["Envisage.Logger"];
  var Envisage_Record = $PS["Envisage.Record"];
  var Foreign_Object = $PS["Foreign.Object"];
  var Type_Data_RowList = $PS["Type.Data.RowList"];                
  var Var = (function () {
      function Var(value0) {
          this.value0 = value0;
      };
      Var.create = function (value0) {
          return new Var(value0);
      };
      return Var;
  })();
  var MissingError = (function () {
      function MissingError(value0) {
          this.value0 = value0;
      };
      MissingError.create = function (value0) {
          return new MissingError(value0);
      };
      return MissingError;
  })();
  var ParseError = (function () {
      function ParseError(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ParseError.create = function (value0) {
          return function (value1) {
              return new ParseError(value0, value1);
          };
      };
      return ParseError;
  })();
  var ValueSupplied = (function () {
      function ValueSupplied(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ValueSupplied.create = function (value0) {
          return function (value1) {
              return new ValueSupplied(value0, value1);
          };
      };
      return ValueSupplied;
  })();
  var DefaultUsed = (function () {
      function DefaultUsed(value0) {
          this.value0 = value0;
      };
      DefaultUsed.create = function (value0) {
          return new DefaultUsed(value0);
      };
      return DefaultUsed;
  })();
  var OptionalNotSupplied = (function () {
      function OptionalNotSupplied(value0) {
          this.value0 = value0;
      };
      OptionalNotSupplied.create = function (value0) {
          return new OptionalNotSupplied(value0);
      };
      return OptionalNotSupplied;
  })();
  var EnvisageInternal = (function () {
      function EnvisageInternal() {

      };
      EnvisageInternal.value = new EnvisageInternal();
      return EnvisageInternal;
  })();
  var EnvError = (function () {
      function EnvError(value0) {
          this.value0 = value0;
      };
      EnvError.create = function (value0) {
          return new EnvError(value0);
      };
      return EnvError;
  })();
  var Component = (function () {
      function Component(value0) {
          this.value0 = value0;
      };
      Component.create = function (value0) {
          return new Component(value0);
      };
      return Component;
  })();
  var ReadValue = function (readValue) {
      this.readValue = readValue;
  };
  var withShow = function (showVal) {
      return function (v) {
          return Var.create({
              varName: v.value0.varName,
              description: v.value0.description,
              parser: v.value0.parser,
              "default": v["value0"]["default"],
              showValue: Data_Functor.map(Data_Functor.functorFn)(Data_Maybe.Just.create)(showVal)
          });
      };
  };
  var varInfo = function (v) {
      return {
          varName: v.value0.varName,
          description: v.value0.description,
          "default": Control_Bind.join(Data_Maybe.bindMaybe)(Data_Functor.map(Data_Maybe.functorMaybe)(v.value0.showValue)(v["value0"]["default"]))
      };
  };
  var success = function (v) {
      return function (val) {
          var valStrM = v.value0.showValue(val);
          return Envisage_Logger.loggerT([ new ValueSupplied(varInfo(v), valStrM) ])(new Data_Maybe.Just(val));
      };
  };
  var showParsed = function (dictShow) {
      return withShow(Data_Show.show(dictShow));
  };
  var readValue = function (dict) {
      return dict.readValue;
  };
  var readValueFromEnv = function (dictReadValue) {
      return function (v) {
          return Envisage_Logger.readerLoggerT(function (env) {
              return readValue(dictReadValue)(v)(Foreign_Object.lookup(v.value0.varName)(env));
          });
      };
  };
  var readEnv$prime = function (dictRowToList) {
      return function (dictRowToList1) {
          return function (dictRecordUpdate) {
              return Envisage_Record.recordUpdate(dictRecordUpdate)(Type_Data_RowList.RLProxy.value)(Type_Data_RowList.RLProxy.value)(EnvisageInternal.value);
          };
      };
  };
  var readEnv = function (dictRowToList) {
      return function (dictRowToList1) {
          return function (dictRecordUpdate) {
              return function (env) {
                  return function (vars) {
                      var v = Envisage_Logger.runReaderLoggerT(env)(readEnv$prime()()(dictRecordUpdate)(vars));
                      return Data_Either.note(new EnvError(v.value0))(v.value1);
                  };
              };
          };
      };
  };
  var parseError = function ($$var) {
      return function (err) {
          return Envisage_Logger.loggerT([ new ParseError(varInfo($$var), err) ])(Data_Maybe.Nothing.value);
      };
  };
  var mkComponent = function (dictRowToList) {
      return function (dictRowToList1) {
          return function (dictRecordUpdate) {
              return function (vars) {
                  return function (ctr) {
                      var config = readEnv$prime()()(dictRecordUpdate)(vars);
                      return new Component(Data_Functor.map(Envisage_Logger.functorReaderLogger(Data_Maybe.functorMaybe))(ctr)(config));
                  };
              };
          };
      };
  };
  var missingError = function ($$var) {
      return Envisage_Logger.loggerT([ new MissingError(varInfo($$var)) ])(Data_Maybe.Nothing.value);
  };
  var hasFunctionReadVar = function (dictReadValue) {
      return new Envisage_Record.HasFunction(function (v) {
          return readValueFromEnv(dictReadValue);
      });
  };
  var hasFunctionReadRecord = function (dictRowToList) {
      return function (dictRowToList1) {
          return function (dictRecordUpdate) {
              return new Envisage_Record.HasFunction(function (v) {
                  return Envisage_Record.recordUpdate(dictRecordUpdate)(Type_Data_RowList.RLProxy.value)(Type_Data_RowList.RLProxy.value)(EnvisageInternal.value);
              });
          };
      };
  };
  var hasFunctionReadComponent = new Envisage_Record.HasFunction(function (v) {
      return function (v1) {
          return v1.value0;
      };
  });
  var describe = function (desc) {
      return function (v) {
          return Var.create({
              varName: v.value0.varName,
              description: new Data_Maybe.Just(desc),
              parser: v.value0.parser,
              "default": v["value0"]["default"],
              showValue: v.value0.showValue
          });
      };
  };
  var defaultUsed = function ($$var) {
      return function (val) {
          return Envisage_Logger.loggerT([ new DefaultUsed(varInfo($$var)) ])(new Data_Maybe.Just(val));
      };
  };
  var readValueAll = new ReadValue(function (v) {
      return function (v1) {
          if (v1 instanceof Data_Maybe.Just) {
              return Data_Either.either(parseError(v))(success(v))(v.value0.parser(v1.value0));
          };
          if (v1 instanceof Data_Maybe.Nothing) {
              return Data_Maybe.maybe(missingError(v))(defaultUsed(v))(v["value0"]["default"]);
          };
          throw new Error("Failed pattern match at Envisage.Internal (line 97, column 6 - line 99, column 93): " + [ v.constructor.name, v1.constructor.name ]);
      };
  });
  var defaultTo = function (def) {
      return function (v) {
          return Var.create({
              varName: v.value0.varName,
              description: v.value0.description,
              parser: v.value0.parser,
              "default": new Data_Maybe.Just(def),
              showValue: v.value0.showValue
          });
      };
  };
  exports["MissingError"] = MissingError;
  exports["ParseError"] = ParseError;
  exports["ValueSupplied"] = ValueSupplied;
  exports["DefaultUsed"] = DefaultUsed;
  exports["OptionalNotSupplied"] = OptionalNotSupplied;
  exports["Var"] = Var;
  exports["mkComponent"] = mkComponent;
  exports["readEnv"] = readEnv;
  exports["defaultTo"] = defaultTo;
  exports["describe"] = describe;
  exports["showParsed"] = showParsed;
  exports["readValueAll"] = readValueAll;
  exports["hasFunctionReadVar"] = hasFunctionReadVar;
  exports["hasFunctionReadRecord"] = hasFunctionReadRecord;
  exports["hasFunctionReadComponent"] = hasFunctionReadComponent;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Envisage.Console"] = $PS["Envisage.Console"] || {};
  var exports = $PS["Envisage.Console"];
  var Chalk = $PS["Chalk"];
  var Data_Array = $PS["Data.Array"];
  var Data_Boolean = $PS["Data.Boolean"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_List = $PS["Data.List"];
  var Data_List_Types = $PS["Data.List.Types"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_String_CodePoints = $PS["Data.String.CodePoints"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Data_Unfoldable = $PS["Data.Unfoldable"];
  var Envisage_Internal = $PS["Envisage.Internal"];                
  var VarName = (function () {
      function VarName(value0) {
          this.value0 = value0;
      };
      VarName.create = function (value0) {
          return new VarName(value0);
      };
      return VarName;
  })();
  var Description = (function () {
      function Description() {

      };
      Description.value = new Description();
      return Description;
  })();
  var Status = (function () {
      function Status(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Status.create = function (value0) {
          return function (value1) {
              return new Status(value0, value1);
          };
      };
      return Status;
  })();
  var Value = (function () {
      function Value(value0) {
          this.value0 = value0;
      };
      Value.create = function (value0) {
          return new Value(value0);
      };
      return Value;
  })();
  var DefaultValue = (function () {
      function DefaultValue() {

      };
      DefaultValue.value = new DefaultValue();
      return DefaultValue;
  })();
  var NoValue = (function () {
      function NoValue() {

      };
      NoValue.value = new NoValue();
      return NoValue;
  })();
  var None = (function () {
      function None() {

      };
      None.value = new None();
      return None;
  })();
  var tableToString = (function () {
      var $61 = Data_String_Common.joinWith("\x0a");
      var $62 = Data_List.toUnfoldable(Data_Unfoldable.unfoldableArray);
      var $63 = Data_Functor.map(Data_List_Types.functorList)((function () {
          var $65 = Data_String_Common.joinWith(" ");
          var $66 = Data_List.toUnfoldable(Data_Unfoldable.unfoldableArray);
          return function ($67) {
              return $65($66($67));
          };
      })());
      return function ($64) {
          return $61($62($63($64)));
      };
  })();
  var resultOrder = function (v) {
      if (v instanceof Envisage_Internal.MissingError) {
          return new Data_Tuple.Tuple(1, v.value0.varName);
      };
      if (v instanceof Envisage_Internal.ParseError) {
          return new Data_Tuple.Tuple(0, v.value0.varName);
      };
      if (v instanceof Envisage_Internal.ValueSupplied) {
          return new Data_Tuple.Tuple(2, v.value0.varName);
      };
      if (v instanceof Envisage_Internal.DefaultUsed) {
          return new Data_Tuple.Tuple(3, v.value0.varName);
      };
      if (v instanceof Envisage_Internal.OptionalNotSupplied) {
          return new Data_Tuple.Tuple(4, v.value0.varName);
      };
      throw new Error("Failed pattern match at Envisage.Console (line 76, column 1 - line 76, column 46): " + [ v.constructor.name ]);
  };
  var printToken = function (v) {
      return function (v1) {
          if (v1 instanceof VarName) {
              return v1.value0(v.varName);
          };
          if (v1 instanceof Description) {
              return Data_Maybe.maybe(Chalk.gray("<no-description>"))(Chalk.white)(v.description);
          };
          if (v1 instanceof Status) {
              return v1.value0(v1.value1);
          };
          if (v1 instanceof Value) {
              return Chalk.green(Data_Maybe.fromMaybe("<not-shown>")(v1.value0));
          };
          if (v1 instanceof DefaultValue) {
              return Chalk.yellow(Data_Maybe.fromMaybe("<not-shown>")(v["default"]) + " (default)");
          };
          if (v1 instanceof NoValue) {
              return Chalk.gray("-");
          };
          if (v1 instanceof None) {
              return "";
          };
          throw new Error("Failed pattern match at Envisage.Console (line 35, column 1 - line 35, column 41): " + [ v.constructor.name, v1.constructor.name ]);
      };
  };
  var runTokens = function (varInfo) {
      return function (tokens) {
          return Data_List.fromFoldable(Data_Foldable.foldableArray)(Data_Functor.map(Data_Functor.functorArray)(printToken(varInfo))(tokens));
      };
  };
  var printErrorForConsole = function (v) {
      if (v instanceof Envisage_Internal.MissingError) {
          return runTokens(v.value0)([ new VarName(Chalk.red), new Status(Chalk.red, "[REQUIRED]"), NoValue.value, Description.value ]);
      };
      if (v instanceof Envisage_Internal.ParseError) {
          return runTokens(v.value0)([ new VarName(Chalk.red), new Status(Chalk.red, "[INVALID]"), new Status(Chalk.red, v.value1), Description.value ]);
      };
      if (v instanceof Envisage_Internal.ValueSupplied) {
          return runTokens(v.value0)([ new VarName(Chalk.green), new Status(Chalk.green, "[SUPPLIED]"), new Value(v.value1), Description.value ]);
      };
      if (v instanceof Envisage_Internal.DefaultUsed) {
          return runTokens(v.value0)([ new VarName(Chalk.yellow), new Status(Chalk.yellow, "[OPTIONAL]"), DefaultValue.value, Description.value ]);
      };
      if (v instanceof Envisage_Internal.OptionalNotSupplied) {
          return runTokens(v.value0)([ new VarName(Chalk.yellow), new Status(Chalk.yellow, "[OPTIONAL]"), NoValue.value, Description.value ]);
      };
      throw new Error("Failed pattern match at Envisage.Console (line 47, column 1 - line 47, column 50): " + [ v.constructor.name ]);
  };
  var padTo = function ($copy_n) {
      return function ($copy_s) {
          var $tco_var_n = $copy_n;
          var $tco_done = false;
          var $tco_result;
          function $tco_loop(n, s) {
              if (n > Data_String_CodePoints.length(s)) {
                  $tco_var_n = n;
                  $copy_s = s + " ";
                  return;
              };
              if (Data_Boolean.otherwise) {
                  $tco_done = true;
                  return s;
              };
              throw new Error("Failed pattern match at Envisage.Console (line 17, column 1 - line 17, column 33): " + [ n.constructor.name, s.constructor.name ]);
          };
          while (!$tco_done) {
              $tco_result = $tco_loop($tco_var_n, $copy_s);
          };
          return $tco_result;
      };
  };
  var colWidths = function (v) {
      if (v instanceof Data_List_Types.Nil) {
          return Data_List_Types.Nil.value;
      };
      var tails = Data_List.catMaybes(Data_Functor.map(Data_List_Types.functorList)(Data_List.tail)(v));
      var heads = Data_Functor.map(Data_List_Types.functorList)(Data_String_CodePoints.length)(Data_List.catMaybes(Data_Functor.map(Data_List_Types.functorList)(Data_List.head)(v)));
      return new Data_List_Types.Cons(Data_Maybe.fromMaybe(0)(Data_Foldable.maximum(Data_Ord.ordInt)(Data_List_Types.foldableList)(heads)), colWidths(tails));
  };
  var alignRow = function (v) {
      return function (v1) {
          if (v instanceof Data_List_Types.Cons && v1 instanceof Data_List_Types.Cons) {
              return new Data_List_Types.Cons(padTo(v.value0)(v1.value0), alignRow(v.value1)(v1.value1));
          };
          return Data_List_Types.Nil.value;
      };
  };
  var alignColumns = function (arr) {
      var widths = colWidths(arr);
      return Data_Functor.map(Data_List_Types.functorList)(alignRow(widths))(arr);
  };
  var printErrorsForConsole = function (v) {
      return tableToString(alignColumns(Data_Functor.map(Data_List_Types.functorList)(printErrorForConsole)(Data_List.fromFoldable(Data_Foldable.foldableArray)(Data_Array.sortWith(Data_Tuple.ordTuple(Data_Ord.ordInt)(Data_Ord.ordString))(resultOrder)(v.value0)))));
  };
  exports["printErrorsForConsole"] = printErrorsForConsole;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Envisage.Var"] = $PS["Envisage.Var"] || {};
  var exports = $PS["Envisage.Var"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Int = $PS["Data.Int"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Envisage_Internal = $PS["Envisage.Internal"];                
  var ParseValue = function (parseValue) {
      this.parseValue = parseValue;
  };
  var parseValueString = new ParseValue(Data_Either.Right.create);
  var parseValueInt = new ParseValue(function (s) {
      var v = Data_Int.fromString(s);
      if (v instanceof Data_Maybe.Just) {
          return new Data_Either.Right(v.value0);
      };
      if (v instanceof Data_Maybe.Nothing) {
          return new Data_Either.Left("Invalid int");
      };
      throw new Error("Failed pattern match at Envisage.Var (line 23, column 18 - line 25, column 34): " + [ v.constructor.name ]);
  });
  var parseValue = function (dict) {
      return dict.parseValue;
  };
  var $$var = function (dictParseValue) {
      return function (varName) {
          return new Envisage_Internal.Var({
              varName: varName,
              description: Data_Maybe.Nothing.value,
              "default": Data_Maybe.Nothing.value,
              showValue: Data_Function["const"](Data_Maybe.Nothing.value),
              parser: parseValue(dictParseValue)
          });
      };
  };
  exports["var"] = $$var;
  exports["parseValueInt"] = parseValueInt;
  exports["parseValueString"] = parseValueString;
})(PS);
(function(exports) {
  "use strict";
  var http =require("http"); 

  exports.createServer = function (handleRequest) {
    return function () {
      return http.createServer(function (req, res) {
        handleRequest(req)(res)();
      });
    };
  };

  exports.listenImpl = function (server) {
    return function (port) {
      return function (hostname) {
        return function (backlog) {
          return function (done) {
            return function () {
              if (backlog !== null) {
                server.listen(port, hostname, backlog, done);
              } else {
                server.listen(port, hostname, done);
              }
            };
          };
        };
      };
    };
  };

  exports.closeImpl = function (server) {
    return function (done) {
      return function () {
        server.close(done);
      };
    };
  };

  exports.setHeader = function (res) {
    return function (key) {
      return function (value) {
        return function () {
          res.setHeader(key, value);
        };
      };
    };
  };

  exports.setStatusCode = function (res) {
    return function (code) {
      return function () {
        res.statusCode = code;
      };
    };
  };
})(PS["Node.HTTP"] = PS["Node.HTTP"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.HTTP"] = $PS["Node.HTTP"] || {};
  var exports = $PS["Node.HTTP"];
  var $foreign = $PS["Node.HTTP"];
  var Data_Nullable = $PS["Data.Nullable"];
  var Unsafe_Coerce = $PS["Unsafe.Coerce"];                
  var responseAsStream = Unsafe_Coerce.unsafeCoerce;
  var requestURL = function ($4) {
      return $4.url;
  };
  var requestMethod = function ($5) {
      return $5.method;
  };
  var requestHeaders = function ($6) {
      return $6.headers;
  };
  var requestAsStream = Unsafe_Coerce.unsafeCoerce;
  var listen = function (server) {
      return function (opts) {
          return function (done) {
              return $foreign.listenImpl(server)(opts.port)(opts.hostname)(Data_Nullable.toNullable(opts.backlog))(done);
          };
      };
  };
  var httpVersion = function ($7) {
      return $7.httpVersion;
  };
  var close = function (server) {
      return function (done) {
          return $foreign.closeImpl(server)(done);
      };
  };
  exports["listen"] = listen;
  exports["close"] = close;
  exports["httpVersion"] = httpVersion;
  exports["requestHeaders"] = requestHeaders;
  exports["requestMethod"] = requestMethod;
  exports["requestURL"] = requestURL;
  exports["requestAsStream"] = requestAsStream;
  exports["responseAsStream"] = responseAsStream;
  exports["createServer"] = $foreign.createServer;
  exports["setHeader"] = $foreign.setHeader;
  exports["setStatusCode"] = $foreign.setStatusCode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Headers"] = $PS["HTTPure.Headers"] || {};
  var exports = $PS["HTTPure.Headers"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Map_Internal = $PS["Data.Map.Internal"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_String_CaseInsensitive = $PS["Data.String.CaseInsensitive"];
  var Data_TraversableWithIndex = $PS["Data.TraversableWithIndex"];
  var Effect = $PS["Effect"];
  var Foreign_Object = $PS["Foreign.Object"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var Headers = function (x) {
      return x;
  };
  var write = function (response) {
      return function (v) {
          var writeField = function (key) {
              return function (value) {
                  return Node_HTTP.setHeader(response)(Data_Newtype.unwrap(Data_String_CaseInsensitive.newtypeCaseInsensitiveString)(key))(value);
              };
          };
          return Data_Functor["void"](Effect.functorEffect)(Data_TraversableWithIndex.traverseWithIndex(Data_Map_Internal.traversableWithIndexMap)(Effect.applicativeEffect)(writeField)(v));
      };
  }; 
  var semigroup = new Data_Semigroup.Semigroup(function (v) {
      return function (v1) {
          return Headers(Data_Map_Internal.union(Data_String_CaseInsensitive.ordCaseInsensitiveString)(v1)(v));
      };
  });
  var read = (function () {
      var insertField = function (x) {
          return function (key) {
              return function (value) {
                  return Data_Map_Internal.insert(Data_String_CaseInsensitive.ordCaseInsensitiveString)(key)(value)(x);
              };
          };
      };
      var $24 = Foreign_Object.fold(insertField)(Data_Map_Internal.empty);
      return function ($25) {
          return Headers($24(Node_HTTP.requestHeaders($25)));
      };
  })();
  var newtypeHeaders = new Data_Newtype.Newtype(function (n) {
      return n;
  }, Headers);
  var header = function (key) {
      var $28 = Data_Map_Internal.singleton(key);
      return function ($29) {
          return Headers($28($29));
      };
  }; 
  var empty = Data_Map_Internal.empty;
  exports["empty"] = empty;
  exports["header"] = header;
  exports["read"] = read;
  exports["write"] = write;
  exports["newtypeHeaders"] = newtypeHeaders;
  exports["semigroup"] = semigroup;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Buffer.Class"] = $PS["Node.Buffer.Class"] || {};
  var exports = $PS["Node.Buffer.Class"];
  var MutableBuffer = function (Monad0, concat, concat$prime, copy, create, fill, freeze, fromArray, fromArrayBuffer, fromString, getAtOffset, read, readString, setAtOffset, size, slice, thaw, toArray, toArrayBuffer, toString, unsafeFreeze, unsafeThaw, write, writeString) {
      this.Monad0 = Monad0;
      this.concat = concat;
      this["concat'"] = concat$prime;
      this.copy = copy;
      this.create = create;
      this.fill = fill;
      this.freeze = freeze;
      this.fromArray = fromArray;
      this.fromArrayBuffer = fromArrayBuffer;
      this.fromString = fromString;
      this.getAtOffset = getAtOffset;
      this.read = read;
      this.readString = readString;
      this.setAtOffset = setAtOffset;
      this.size = size;
      this.slice = slice;
      this.thaw = thaw;
      this.toArray = toArray;
      this.toArrayBuffer = toArrayBuffer;
      this.toString = toString;
      this.unsafeFreeze = unsafeFreeze;
      this.unsafeThaw = unsafeThaw;
      this.write = write;
      this.writeString = writeString;
  };
  var toString = function (dict) {
      return dict.toString;
  };
  var size = function (dict) {
      return dict.size;
  };
  var fromString = function (dict) {
      return dict.fromString;
  };
  var concat = function (dict) {
      return dict.concat;
  };
  exports["MutableBuffer"] = MutableBuffer;
  exports["fromString"] = fromString;
  exports["toString"] = toString;
  exports["size"] = size;
  exports["concat"] = concat;
})(PS);
(function(exports) {
  /* global exports */
  /* global Buffer */
  "use strict";

  exports.copyAll = function(a) {
    return function() {
      return Buffer.from(a);
    };
  };

  exports.writeInternal = function (ty) {
    return function (value) {
      return function (offset) {
        return function (buf) {
          return function() {
            buf['write' + ty](value, offset);
            return {};
          }
        };
      };
    };
  };

  exports.writeStringInternal = function (encoding) {
    return function (offset) {
      return function (length) {
        return function (value) {
          return function (buff) {
            return function() {
              return buff.write(value, offset, length, encoding);
            }
          };
        };
      };
    };
  };

  exports.setAtOffset = function (value) {
    return function (offset) {
      return function (buff) {
        return function() {
          buff[offset] = value;
          return {};
        };
      };
    };
  };

  exports.copy = function (srcStart) {
    return function (srcEnd) {
      return function (src) {
        return function (targStart) {
          return function (targ) {
            return function() {
              return src.copy(targ, targStart, srcStart, srcEnd);
            };
          };
        };
      };
    };
  };

  exports.fill = function (octet) {
    return function (start) {
      return function (end) {
        return function (buf) {
          return function() {
            buf.fill(octet, start, end);
            return {};
          };
        };
      };
    };
  };
})(PS["Node.Buffer.Internal"] = PS["Node.Buffer.Internal"] || {});
(function(exports) {
  /* global exports */
  /* global Buffer */
  /* global require */
  "use strict";

  exports.create = function (size) {
    return Buffer.alloc(size);
  };

  exports.fromArray = function (octets) {
    return Buffer.from(octets);
  };

  exports.size = function (buff) {
    return buff.length;
  };

  exports.toArray = function (buff) {
    var json = buff.toJSON()
    return json.data || json;
  };

  exports.toArrayBuffer = function(buff) {
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
  };

  exports.fromArrayBuffer = function(ab) {
    return Buffer.from(ab);
  };

  exports.fromStringImpl = function (str) {
    return function (encoding) {
      return Buffer.from(str, encoding);
    };
  };

  exports.readImpl = function (ty) {
    return function (offset) {
      return function (buf) {
        return buf['read' + ty](offset);
      };
    };
  };

  exports.readStringImpl = function (enc) {
    return function (start) {
      return function (end) {
        return function (buff) {
          return buff.toString(enc, start, end);
        };
      };
    };
  };

  exports.getAtOffsetImpl = function (just) {
    return function (nothing) {
      return function (offset) {
        return function (buff) {
          var octet = buff[offset];
          return octet == null ? nothing
                               : just(octet);
        };
      };
    };
  };

  exports.toStringImpl = function (enc) {
    return function (buff) {
      return buff.toString(enc);
    };
  };

  exports.slice = function (start) {
    return function (end) {
      return function (buff) {
        return buff.slice(start, end);
      };
    };
  };

  exports.concat = function (buffs) {
    return Buffer.concat(buffs);
  };

  exports["concat'"] = function (buffs) {
    return function (totalLength) {
      return Buffer.concat(buffs, totalLength);
    };
  };
})(PS["Node.Buffer.Immutable"] = PS["Node.Buffer.Immutable"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Buffer.Types"] = $PS["Node.Buffer.Types"] || {};
  var exports = $PS["Node.Buffer.Types"];
  var Data_Show = $PS["Data.Show"];                
  var UInt8 = (function () {
      function UInt8() {

      };
      UInt8.value = new UInt8();
      return UInt8;
  })();
  var UInt16LE = (function () {
      function UInt16LE() {

      };
      UInt16LE.value = new UInt16LE();
      return UInt16LE;
  })();
  var UInt16BE = (function () {
      function UInt16BE() {

      };
      UInt16BE.value = new UInt16BE();
      return UInt16BE;
  })();
  var UInt32LE = (function () {
      function UInt32LE() {

      };
      UInt32LE.value = new UInt32LE();
      return UInt32LE;
  })();
  var UInt32BE = (function () {
      function UInt32BE() {

      };
      UInt32BE.value = new UInt32BE();
      return UInt32BE;
  })();
  var Int8 = (function () {
      function Int8() {

      };
      Int8.value = new Int8();
      return Int8;
  })();
  var Int16LE = (function () {
      function Int16LE() {

      };
      Int16LE.value = new Int16LE();
      return Int16LE;
  })();
  var Int16BE = (function () {
      function Int16BE() {

      };
      Int16BE.value = new Int16BE();
      return Int16BE;
  })();
  var Int32LE = (function () {
      function Int32LE() {

      };
      Int32LE.value = new Int32LE();
      return Int32LE;
  })();
  var Int32BE = (function () {
      function Int32BE() {

      };
      Int32BE.value = new Int32BE();
      return Int32BE;
  })();
  var FloatLE = (function () {
      function FloatLE() {

      };
      FloatLE.value = new FloatLE();
      return FloatLE;
  })();
  var FloatBE = (function () {
      function FloatBE() {

      };
      FloatBE.value = new FloatBE();
      return FloatBE;
  })();
  var DoubleLE = (function () {
      function DoubleLE() {

      };
      DoubleLE.value = new DoubleLE();
      return DoubleLE;
  })();
  var DoubleBE = (function () {
      function DoubleBE() {

      };
      DoubleBE.value = new DoubleBE();
      return DoubleBE;
  })();
  var showBufferValueType = new Data_Show.Show(function (v) {
      if (v instanceof UInt8) {
          return "UInt8";
      };
      if (v instanceof UInt16LE) {
          return "UInt16LE";
      };
      if (v instanceof UInt16BE) {
          return "UInt16BE";
      };
      if (v instanceof UInt32LE) {
          return "UInt32LE";
      };
      if (v instanceof UInt32BE) {
          return "UInt32BE";
      };
      if (v instanceof Int8) {
          return "Int8";
      };
      if (v instanceof Int16LE) {
          return "Int16LE";
      };
      if (v instanceof Int16BE) {
          return "Int16BE";
      };
      if (v instanceof Int32LE) {
          return "Int32LE";
      };
      if (v instanceof Int32BE) {
          return "Int32BE";
      };
      if (v instanceof FloatLE) {
          return "FloatLE";
      };
      if (v instanceof FloatBE) {
          return "FloatBE";
      };
      if (v instanceof DoubleLE) {
          return "DoubleLE";
      };
      if (v instanceof DoubleBE) {
          return "DoubleBE";
      };
      throw new Error("Failed pattern match at Node.Buffer.Types (line 33, column 1 - line 47, column 29): " + [ v.constructor.name ]);
  });
  exports["showBufferValueType"] = showBufferValueType;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Encoding"] = $PS["Node.Encoding"] || {};
  var exports = $PS["Node.Encoding"];
  var Data_Show = $PS["Data.Show"];                
  var ASCII = (function () {
      function ASCII() {

      };
      ASCII.value = new ASCII();
      return ASCII;
  })();
  var UTF8 = (function () {
      function UTF8() {

      };
      UTF8.value = new UTF8();
      return UTF8;
  })();
  var UTF16LE = (function () {
      function UTF16LE() {

      };
      UTF16LE.value = new UTF16LE();
      return UTF16LE;
  })();
  var UCS2 = (function () {
      function UCS2() {

      };
      UCS2.value = new UCS2();
      return UCS2;
  })();
  var Base64 = (function () {
      function Base64() {

      };
      Base64.value = new Base64();
      return Base64;
  })();
  var Latin1 = (function () {
      function Latin1() {

      };
      Latin1.value = new Latin1();
      return Latin1;
  })();
  var Binary = (function () {
      function Binary() {

      };
      Binary.value = new Binary();
      return Binary;
  })();
  var Hex = (function () {
      function Hex() {

      };
      Hex.value = new Hex();
      return Hex;
  })();
  var showEncoding = new Data_Show.Show(function (v) {
      if (v instanceof ASCII) {
          return "ASCII";
      };
      if (v instanceof UTF8) {
          return "UTF8";
      };
      if (v instanceof UTF16LE) {
          return "UTF16LE";
      };
      if (v instanceof UCS2) {
          return "UCS2";
      };
      if (v instanceof Base64) {
          return "Base64";
      };
      if (v instanceof Latin1) {
          return "Latin1";
      };
      if (v instanceof Binary) {
          return "Binary";
      };
      if (v instanceof Hex) {
          return "Hex";
      };
      throw new Error("Failed pattern match at Node.Encoding (line 19, column 1 - line 27, column 23): " + [ v.constructor.name ]);
  });
  var encodingToNode = function (v) {
      if (v instanceof ASCII) {
          return "ascii";
      };
      if (v instanceof UTF8) {
          return "utf8";
      };
      if (v instanceof UTF16LE) {
          return "utf16le";
      };
      if (v instanceof UCS2) {
          return "ucs2";
      };
      if (v instanceof Base64) {
          return "base64";
      };
      if (v instanceof Latin1) {
          return "latin1";
      };
      if (v instanceof Binary) {
          return "binary";
      };
      if (v instanceof Hex) {
          return "hex";
      };
      throw new Error("Failed pattern match at Node.Encoding (line 31, column 1 - line 31, column 37): " + [ v.constructor.name ]);
  };
  exports["UTF8"] = UTF8;
  exports["encodingToNode"] = encodingToNode;
  exports["showEncoding"] = showEncoding;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Buffer.Immutable"] = $PS["Node.Buffer.Immutable"] || {};
  var exports = $PS["Node.Buffer.Immutable"];
  var $foreign = $PS["Node.Buffer.Immutable"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];
  var Node_Buffer_Types = $PS["Node.Buffer.Types"];
  var Node_Encoding = $PS["Node.Encoding"];                
  var toString = function ($3) {
      return $foreign.toStringImpl(Node_Encoding.encodingToNode($3));
  };                                                     
  var readString = function ($4) {
      return $foreign.readStringImpl(Node_Encoding.encodingToNode($4));
  };
  var read = (function () {
      var $5 = Data_Show.show(Node_Buffer_Types.showBufferValueType);
      return function ($6) {
          return $foreign.readImpl($5($6));
      };
  })();
  var getAtOffset = $foreign.getAtOffsetImpl(Data_Maybe.Just.create)(Data_Maybe.Nothing.value);
  var fromString = function (str) {
      var $7 = $foreign.fromStringImpl(str);
      return function ($8) {
          return $7(Node_Encoding.encodingToNode($8));
      };
  };
  exports["fromString"] = fromString;
  exports["read"] = read;
  exports["readString"] = readString;
  exports["toString"] = toString;
  exports["getAtOffset"] = getAtOffset;
  exports["create"] = $foreign.create;
  exports["fromArray"] = $foreign.fromArray;
  exports["fromArrayBuffer"] = $foreign.fromArrayBuffer;
  exports["toArray"] = $foreign.toArray;
  exports["toArrayBuffer"] = $foreign.toArrayBuffer;
  exports["concat"] = $foreign.concat;
  exports["concat'"] = $foreign["concat'"];
  exports["slice"] = $foreign.slice;
  exports["size"] = $foreign.size;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Buffer.Internal"] = $PS["Node.Buffer.Internal"] || {};
  var exports = $PS["Node.Buffer.Internal"];
  var $foreign = $PS["Node.Buffer.Internal"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Show = $PS["Data.Show"];
  var Node_Buffer_Immutable = $PS["Node.Buffer.Immutable"];
  var Node_Buffer_Types = $PS["Node.Buffer.Types"];
  var Node_Encoding = $PS["Node.Encoding"];                
  var writeString = function (dictMonad) {
      return function ($20) {
          return $foreign.writeStringInternal(Node_Encoding.encodingToNode($20));
      };
  };
  var write = function (dictMonad) {
      var $21 = Data_Show.show(Node_Buffer_Types.showBufferValueType);
      return function ($22) {
          return $foreign.writeInternal($21($22));
      };
  };
  var unsafeThaw = function (dictMonad) {
      var $23 = Control_Applicative.pure(dictMonad.Applicative0());
      return function ($24) {
          return $23($24);
      };
  };
  var usingToImmutable = function (dictMonad) {
      return function (f) {
          return function (x) {
              return unsafeThaw(dictMonad)(f(x));
          };
      };
  };
  var unsafeFreeze = function (dictMonad) {
      var $25 = Control_Applicative.pure(dictMonad.Applicative0());
      return function ($26) {
          return $25($26);
      };
  };
  var usingFromImmutable = function (dictMonad) {
      return function (f) {
          return function (buf) {
              return Data_Functor.map(((dictMonad.Bind1()).Apply0()).Functor0())(f)(unsafeFreeze(dictMonad)(buf));
          };
      };
  };
  var toString = function (dictMonad) {
      return function (m) {
          return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.toString(m));
      };
  };
  var toArrayBuffer = function (dictMonad) {
      return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.toArrayBuffer);
  };
  var toArray = function (dictMonad) {
      return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.toArray);
  };
  var slice = Node_Buffer_Immutable.slice;
  var size = function (dictMonad) {
      return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.size);
  };
  var readString = function (dictMonad) {
      return function (m) {
          return function (o) {
              return function (o$prime) {
                  return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.readString(m)(o)(o$prime));
              };
          };
      };
  };
  var read = function (dictMonad) {
      return function (t) {
          return function (o) {
              return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.read(t)(o));
          };
      };
  };
  var getAtOffset = function (dictMonad) {
      return function (o) {
          return usingFromImmutable(dictMonad)(Node_Buffer_Immutable.getAtOffset(o));
      };
  };
  var fromString = function (dictMonad) {
      return function (s) {
          return usingToImmutable(dictMonad)(Node_Buffer_Immutable.fromString(s));
      };
  };
  var fromArrayBuffer = function (dictMonad) {
      return usingToImmutable(dictMonad)(Node_Buffer_Immutable.fromArrayBuffer);
  };
  var fromArray = function (dictMonad) {
      return usingToImmutable(dictMonad)(Node_Buffer_Immutable.fromArray);
  };
  var create = function (dictMonad) {
      return usingToImmutable(dictMonad)(Node_Buffer_Immutable.create);
  };
  var concat$prime = function (dictMonad) {
      return function (arrs) {
          return function (n) {
              return function (v) {
                  return Node_Buffer_Immutable["concat'"](arrs)(n);
              };
          };
      };
  };
  var concat = function (arrs) {
      return function (v) {
          return Node_Buffer_Immutable.concat(arrs);
      };
  };
  exports["unsafeFreeze"] = unsafeFreeze;
  exports["unsafeThaw"] = unsafeThaw;
  exports["create"] = create;
  exports["fromArray"] = fromArray;
  exports["fromString"] = fromString;
  exports["fromArrayBuffer"] = fromArrayBuffer;
  exports["toArrayBuffer"] = toArrayBuffer;
  exports["read"] = read;
  exports["readString"] = readString;
  exports["toString"] = toString;
  exports["write"] = write;
  exports["writeString"] = writeString;
  exports["toArray"] = toArray;
  exports["getAtOffset"] = getAtOffset;
  exports["slice"] = slice;
  exports["size"] = size;
  exports["concat"] = concat;
  exports["concat'"] = concat$prime;
  exports["copyAll"] = $foreign.copyAll;
  exports["setAtOffset"] = $foreign.setAtOffset;
  exports["copy"] = $foreign.copy;
  exports["fill"] = $foreign.fill;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Buffer"] = $PS["Node.Buffer"] || {};
  var exports = $PS["Node.Buffer"];
  var Effect = $PS["Effect"];
  var Node_Buffer_Class = $PS["Node.Buffer.Class"];
  var Node_Buffer_Internal = $PS["Node.Buffer.Internal"];                
  var mutableBufferEffect = new Node_Buffer_Class.MutableBuffer(function () {
      return Effect.monadEffect;
  }, Node_Buffer_Internal.concat, Node_Buffer_Internal["concat'"](Effect.monadEffect), Node_Buffer_Internal.copy, Node_Buffer_Internal.create(Effect.monadEffect), Node_Buffer_Internal.fill, Node_Buffer_Internal.copyAll, Node_Buffer_Internal.fromArray(Effect.monadEffect), Node_Buffer_Internal.fromArrayBuffer(Effect.monadEffect), Node_Buffer_Internal.fromString(Effect.monadEffect), Node_Buffer_Internal.getAtOffset(Effect.monadEffect), Node_Buffer_Internal.read(Effect.monadEffect), Node_Buffer_Internal.readString(Effect.monadEffect), Node_Buffer_Internal.setAtOffset, Node_Buffer_Internal.size(Effect.monadEffect), Node_Buffer_Internal.slice, Node_Buffer_Internal.copyAll, Node_Buffer_Internal.toArray(Effect.monadEffect), Node_Buffer_Internal.toArrayBuffer(Effect.monadEffect), Node_Buffer_Internal.toString(Effect.monadEffect), Node_Buffer_Internal.unsafeFreeze(Effect.monadEffect), Node_Buffer_Internal.unsafeThaw(Effect.monadEffect), Node_Buffer_Internal.write(Effect.monadEffect), Node_Buffer_Internal.writeString(Effect.monadEffect));
  exports["mutableBufferEffect"] = mutableBufferEffect;
})(PS);
(function(exports) {
  "use strict";

  exports.readChunkImpl = function (Left) {
    return function (Right) {
      return function (chunk) {
        if (chunk instanceof Buffer) {
          return Right(chunk);
        } else if (typeof chunk === "string") {
          return Left(chunk);
        } else {
          throw new Error(
            "Node.Stream.readChunkImpl: Unrecognised " +
            "chunk type; expected String or Buffer, got: " +
            chunk);
        }
      };
    };
  };

  exports.onDataEitherImpl = function (readChunk) {
    return function (r) {
      return function (f) {
        return function () {
          r.on("data", function (data) {
            f(readChunk(data))();
          });
        };
      };
    };
  };

  exports.onEnd = function (s) {
    return function (f) {
      return function () {
        s.on("end", f);
      };
    };
  };

  exports.write = function (w) {
    return function (chunk) {
      return function (done) {
        return function () {
          return w.write(chunk, null, done);
        };
      };
    };
  };

  exports.writeStringImpl = function (w) {
    return function (enc) {
      return function (s) {
        return function (done) {
          return function () {
            return w.write(s, enc, done);
          };
        };
      };
    };
  };

  exports.end = function (w) {
    return function (done) {
      return function () {
        w.end(null, null, function () {
          done();
        });
      };
    };
  };
})(PS["Node.Stream"] = PS["Node.Stream"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Stream"] = $PS["Node.Stream"] || {};
  var exports = $PS["Node.Stream"];
  var $foreign = $PS["Node.Stream"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Either = $PS["Data.Either"];
  var Data_Show = $PS["Data.Show"];
  var Effect = $PS["Effect"];
  var Effect_Exception = $PS["Effect.Exception"];
  var Node_Encoding = $PS["Node.Encoding"];                
  var writeString = function (w) {
      return function (enc) {
          return $foreign.writeStringImpl(w)(Data_Show.show(Node_Encoding.showEncoding)(enc));
      };
  };
  var readChunk = $foreign.readChunkImpl(Data_Either.Left.create)(Data_Either.Right.create);
  var onDataEither = function (r) {
      return function (cb) {
          return $foreign.onDataEitherImpl(readChunk)(r)(cb);
      };
  };
  var onData = function (r) {
      return function (cb) {
          var fromEither = function (x) {
              if (x instanceof Data_Either.Left) {
                  return Effect_Exception["throw"]("Stream encoding should not be set");
              };
              if (x instanceof Data_Either.Right) {
                  return Control_Applicative.pure(Effect.applicativeEffect)(x.value0);
              };
              throw new Error("Failed pattern match at Node.Stream (line 94, column 5 - line 98, column 17): " + [ x.constructor.name ]);
          };
          return onDataEither(r)(Control_Bind.composeKleisliFlipped(Effect.bindEffect)(cb)(fromEither));
      };
  };
  exports["onData"] = onData;
  exports["writeString"] = writeString;
  exports["onEnd"] = $foreign.onEnd;
  exports["write"] = $foreign.write;
  exports["end"] = $foreign.end;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Body"] = $PS["HTTPure.Body"] || {};
  var exports = $PS["HTTPure.Body"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect = $PS["Effect"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Ref = $PS["Effect.Ref"];
  var HTTPure_Headers = $PS["HTTPure.Headers"];
  var Node_Buffer = $PS["Node.Buffer"];
  var Node_Buffer_Class = $PS["Node.Buffer.Class"];
  var Node_Encoding = $PS["Node.Encoding"];
  var Node_HTTP = $PS["Node.HTTP"];
  var Node_Stream = $PS["Node.Stream"];                    
  var Body = function (defaultHeaders, write) {
      this.defaultHeaders = defaultHeaders;
      this.write = write;
  };
  var write = function (dict) {
      return dict.write;
  };
  var read = function (request) {
      return Effect_Aff.makeAff(function (done) {
          var stream = Node_HTTP.requestAsStream(request);
          return function __do() {
              var bufs = Effect_Ref["new"]([  ])();
              Node_Stream.onData(stream)(function (buf) {
                  return Data_Functor["void"](Effect.functorEffect)(Effect_Ref.modify(function (v) {
                      return Data_Semigroup.append(Data_Semigroup.semigroupArray)(v)([ buf ]);
                  })(bufs));
              })();
              Node_Stream.onEnd(stream)(function __do() {
                  var body = Control_Bind.bind(Effect.bindEffect)(Control_Bind.bind(Effect.bindEffect)(Effect_Ref.read(bufs))(Node_Buffer_Class.concat(Node_Buffer.mutableBufferEffect)))(Node_Buffer_Class.toString(Node_Buffer.mutableBufferEffect)(Node_Encoding.UTF8.value))();
                  return done(new Data_Either.Right(body))();
              })();
              return Effect_Aff.nonCanceler;
          };
      });
  };
  var defaultHeaders = function (dict) {
      return dict.defaultHeaders;
  };
  var bodyBuffer = new Body(function (buf) {
      return Data_Functor.map(Effect.functorEffect)(Data_Functor.map(Data_Functor.functorFn)(HTTPure_Headers.header("Content-Length"))(Data_Show.show(Data_Show.showInt)))(Node_Buffer_Class.size(Node_Buffer.mutableBufferEffect)(buf));
  }, function (body) {
      return function (response) {
          return Effect_Aff.makeAff(function (done) {
              var stream = Node_HTTP.responseAsStream(response);
              return function __do() {
                  Node_Stream.write(stream)(body)(Control_Applicative.pure(Effect.applicativeEffect)(Data_Unit.unit))();
                  Node_Stream.end(stream)(Control_Applicative.pure(Effect.applicativeEffect)(Data_Unit.unit))();
                  done(new Data_Either.Right(Data_Unit.unit))();
                  return Effect_Aff.nonCanceler;
              };
          });
      };
  });
  var bodyString = new Body(function (body) {
      return function __do() {
          var v = Node_Buffer_Class.fromString(Node_Buffer.mutableBufferEffect)(body)(Node_Encoding.UTF8.value)();
          return defaultHeaders(bodyBuffer)(v)();
      };
  }, function (body) {
      return function (response) {
          return Effect_Aff.makeAff(function (done) {
              var stream = Node_HTTP.responseAsStream(response);
              return function __do() {
                  Node_Stream.writeString(stream)(Node_Encoding.UTF8.value)(body)(Control_Applicative.pure(Effect.applicativeEffect)(Data_Unit.unit))();
                  Node_Stream.end(stream)(Control_Applicative.pure(Effect.applicativeEffect)(Data_Unit.unit))();
                  done(new Data_Either.Right(Data_Unit.unit))();
                  return Effect_Aff.nonCanceler;
              };
          });
      };
  });
  exports["defaultHeaders"] = defaultHeaders;
  exports["read"] = read;
  exports["write"] = write;
  exports["bodyString"] = bodyString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Status"] = $PS["HTTPure.Status"] || {};
  var exports = $PS["HTTPure.Status"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var write = Node_HTTP.setStatusCode;
  var internalServerError = 500;
  exports["write"] = write;
  exports["internalServerError"] = internalServerError;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Response"] = $PS["HTTPure.Response"] || {};
  var exports = $PS["HTTPure.Response"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];
  var Effect_Class = $PS["Effect.Class"];
  var HTTPure_Body = $PS["HTTPure.Body"];
  var HTTPure_Headers = $PS["HTTPure.Headers"];
  var HTTPure_Status = $PS["HTTPure.Status"];                
  var send = function (dictMonadEffect) {
      return function (dictMonadAff) {
          return function (httpresponse) {
              return function (v) {
                  return Control_Bind.discard(Control_Bind.discardUnit)(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Class.liftEffect(dictMonadAff.MonadEffect0())(HTTPure_Status.write(httpresponse)(v.status)))(function () {
                      return Control_Bind.discard(Control_Bind.discardUnit)(((dictMonadAff.MonadEffect0()).Monad0()).Bind1())(Effect_Class.liftEffect(dictMonadAff.MonadEffect0())(HTTPure_Headers.write(httpresponse)(v.headers)))(function () {
                          return Effect_Aff_Class.liftAff(dictMonadAff)(v.writeBody(httpresponse));
                      });
                  });
              };
          };
      };
  };
  var response$prime = function (dictMonadAff) {
      return function (dictBody) {
          return function (status) {
              return function (headers) {
                  return function (body) {
                      return Effect_Class.liftEffect(dictMonadAff.MonadEffect0())(function __do() {
                          var defaultHeaders = HTTPure_Body.defaultHeaders(dictBody)(body)();
                          return {
                              status: status,
                              headers: Data_Semigroup.append(HTTPure_Headers.semigroup)(defaultHeaders)(headers),
                              writeBody: HTTPure_Body.write(dictBody)(body)
                          };
                      });
                  };
              };
          };
      };
  };
  var response = function (dictMonadAff) {
      return function (dictBody) {
          return function (status) {
              return response$prime(dictMonadAff)(dictBody)(status)(HTTPure_Headers.empty);
          };
      };
  };
  var internalServerError$prime = function (dictMonadAff) {
      return function (dictBody) {
          return response$prime(dictMonadAff)(dictBody)(HTTPure_Status.internalServerError);
      };
  };
  var internalServerError = function (dictMonadAff) {
      return function (dictBody) {
          return internalServerError$prime(dictMonadAff)(dictBody)(HTTPure_Headers.empty);
      };
  };
  exports["send"] = send;
  exports["response"] = response;
  exports["internalServerError"] = internalServerError;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Method"] = $PS["HTTPure.Method"] || {};
  var exports = $PS["HTTPure.Method"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var Get = (function () {
      function Get() {

      };
      Get.value = new Get();
      return Get;
  })();
  var Post = (function () {
      function Post() {

      };
      Post.value = new Post();
      return Post;
  })();
  var Put = (function () {
      function Put() {

      };
      Put.value = new Put();
      return Put;
  })();
  var Delete = (function () {
      function Delete() {

      };
      Delete.value = new Delete();
      return Delete;
  })();
  var Head = (function () {
      function Head() {

      };
      Head.value = new Head();
      return Head;
  })();
  var Connect = (function () {
      function Connect() {

      };
      Connect.value = new Connect();
      return Connect;
  })();
  var Options = (function () {
      function Options() {

      };
      Options.value = new Options();
      return Options;
  })();
  var Trace = (function () {
      function Trace() {

      };
      Trace.value = new Trace();
      return Trace;
  })();
  var Patch = (function () {
      function Patch() {

      };
      Patch.value = new Patch();
      return Patch;
  })();
  var read = function (request) {
      var v = Node_HTTP.requestMethod(request);
      if (v === "POST") {
          return Post.value;
      };
      if (v === "PUT") {
          return Put.value;
      };
      if (v === "DELETE") {
          return Delete.value;
      };
      if (v === "HEAD") {
          return Head.value;
      };
      if (v === "CONNECT") {
          return Connect.value;
      };
      if (v === "OPTIONS") {
          return Options.value;
      };
      if (v === "TRACE") {
          return Trace.value;
      };
      if (v === "PATCH") {
          return Patch.value;
      };
      return Get.value;
  };
  exports["read"] = read;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Utils"] = $PS["HTTPure.Utils"] || {};
  var exports = $PS["HTTPure.Utils"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Global = $PS["Global"];                              
  var urlDecode = function (s) {
      return Data_Maybe.fromMaybe(s)(Global["decodeURIComponent"](s));
  };
  var replacePlus = Data_String_Common.replace("+")("%20");
  exports["replacePlus"] = replacePlus;
  exports["urlDecode"] = urlDecode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Path"] = $PS["HTTPure.Path"] || {};
  var exports = $PS["HTTPure.Path"];
  var Data_Array = $PS["Data.Array"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_String_Pattern = $PS["Data.String.Pattern"];
  var HTTPure_Utils = $PS["HTTPure.Utils"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var read = (function () {
      var split = function ($0) {
          return Data_String_Common.split(Data_String_Pattern.Pattern($0));
      };
      var nonempty = Data_Array.filter(Data_Eq.notEq(Data_Eq.eqString)(""));
      var first = (function () {
          var $1 = Data_Maybe.fromMaybe("");
          return function ($2) {
              return $1(Data_Array.head($2));
          };
      })();
      var $3 = Data_Functor.map(Data_Functor.functorArray)(HTTPure_Utils.urlDecode);
      var $4 = split("/");
      var $5 = split("?");
      return function ($6) {
          return $3(nonempty($4(first($5(Node_HTTP.requestURL($6))))));
      };
  })();
  exports["read"] = read;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Query"] = $PS["HTTPure.Query"] || {};
  var exports = $PS["HTTPure.Query"];
  var Data_Array = $PS["Data.Array"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_String_Pattern = $PS["Data.String.Pattern"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Foreign_Object = $PS["Foreign.Object"];
  var HTTPure_Utils = $PS["HTTPure.Utils"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var read = (function () {
      var split = function ($0) {
          return Data_String_Common.split(Data_String_Pattern.Pattern($0));
      };
      var nonempty = Data_Array.filter(Data_Eq.notEq(Data_Eq.eqString)(""));
      var last = (function () {
          var $1 = Data_String_Common.joinWith("");
          var $2 = Data_Maybe.fromMaybe([  ]);
          return function ($3) {
              return $1($2(Data_Array.tail($3)));
          };
      })();
      var first = (function () {
          var $4 = Data_Maybe.fromMaybe("");
          return function ($5) {
              return $4(Data_Array.head($5));
          };
      })();
      var decode = function ($6) {
          return HTTPure_Utils.urlDecode(HTTPure_Utils.replacePlus($6));
      };
      var decodeKeyValue = Data_Bifunctor.bimap(Data_Tuple.bifunctorTuple)(decode)(decode);
      var toTuple = function (item) {
          var itemParts = split("=")(item);
          return decodeKeyValue(new Data_Tuple.Tuple(first(itemParts), last(itemParts)));
      };
      var toObject = (function () {
          var $7 = Foreign_Object.fromFoldable(Data_Foldable.foldableArray);
          var $8 = Data_Functor.map(Data_Functor.functorArray)(toTuple);
          return function ($9) {
              return $7($8($9));
          };
      })();
      var $10 = split("&");
      var $11 = split("?");
      return function ($12) {
          return toObject(nonempty($10(last($11(Node_HTTP.requestURL($12))))));
      };
  })();
  exports["read"] = read;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Version"] = $PS["HTTPure.Version"] || {};
  var exports = $PS["HTTPure.Version"];
  var Node_HTTP = $PS["Node.HTTP"];                
  var HTTP0_9 = (function () {
      function HTTP0_9() {

      };
      HTTP0_9.value = new HTTP0_9();
      return HTTP0_9;
  })();
  var HTTP1_0 = (function () {
      function HTTP1_0() {

      };
      HTTP1_0.value = new HTTP1_0();
      return HTTP1_0;
  })();
  var HTTP1_1 = (function () {
      function HTTP1_1() {

      };
      HTTP1_1.value = new HTTP1_1();
      return HTTP1_1;
  })();
  var HTTP2_0 = (function () {
      function HTTP2_0() {

      };
      HTTP2_0.value = new HTTP2_0();
      return HTTP2_0;
  })();
  var HTTP3_0 = (function () {
      function HTTP3_0() {

      };
      HTTP3_0.value = new HTTP3_0();
      return HTTP3_0;
  })();
  var Other = (function () {
      function Other(value0) {
          this.value0 = value0;
      };
      Other.create = function (value0) {
          return new Other(value0);
      };
      return Other;
  })();
  var read = function (request) {
      var v = Node_HTTP.httpVersion(request);
      if (v === "0.9") {
          return HTTP0_9.value;
      };
      if (v === "1.0") {
          return HTTP1_0.value;
      };
      if (v === "1.1") {
          return HTTP1_1.value;
      };
      if (v === "2.0") {
          return HTTP2_0.value;
      };
      if (v === "3.0") {
          return HTTP3_0.value;
      };
      return new Other(v);
  };
  exports["read"] = read;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Request"] = $PS["HTTPure.Request"] || {};
  var exports = $PS["HTTPure.Request"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Effect_Aff = $PS["Effect.Aff"];
  var HTTPure_Body = $PS["HTTPure.Body"];
  var HTTPure_Headers = $PS["HTTPure.Headers"];
  var HTTPure_Method = $PS["HTTPure.Method"];
  var HTTPure_Path = $PS["HTTPure.Path"];
  var HTTPure_Query = $PS["HTTPure.Query"];
  var HTTPure_Version = $PS["HTTPure.Version"];
  var fromHTTPRequest = function (request) {
      return Control_Bind.bind(Effect_Aff.bindAff)(HTTPure_Body.read(request))(function (body) {
          return Control_Applicative.pure(Effect_Aff.applicativeAff)({
              method: HTTPure_Method.read(request),
              path: HTTPure_Path.read(request),
              query: HTTPure_Query.read(request),
              headers: HTTPure_Headers.read(request),
              body: body,
              httpVersion: HTTPure_Version.read(request)
          });
      });
  };
  exports["fromHTTPRequest"] = fromHTTPRequest;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["HTTPure.Server"] = $PS["HTTPure.Server"] || {};
  var exports = $PS["HTTPure.Server"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect = $PS["Effect"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];
  var Effect_Class = $PS["Effect.Class"];
  var Effect_Console = $PS["Effect.Console"];
  var Effect_Exception = $PS["Effect.Exception"];
  var HTTPure_Body = $PS["HTTPure.Body"];
  var HTTPure_Request = $PS["HTTPure.Request"];
  var HTTPure_Response = $PS["HTTPure.Response"];
  var Node_HTTP = $PS["Node.HTTP"];                              
  var onError500 = function (router) {
      return function (request) {
          return Control_Monad_Error_Class.catchError(Effect_Aff.monadErrorAff)(router(request))(function (err) {
              return Control_Bind.discard(Control_Bind.discardUnit)(Effect_Aff.bindAff)(Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(Effect_Console.error(Effect_Exception.message(err))))(function () {
                  return HTTPure_Response.internalServerError(Effect_Aff_Class.monadAffAff)(HTTPure_Body.bodyString)("Internal server error");
              });
          });
      };
  };
  var handleRequest = function (router) {
      return function (request) {
          return function (httpresponse) {
              return Data_Functor["void"](Effect.functorEffect)(Effect_Aff.runAff(function (v) {
                  return Control_Applicative.pure(Effect.applicativeEffect)(Data_Unit.unit);
              })(Control_Bind.bind(Effect_Aff.bindAff)(Control_Bind.bind(Effect_Aff.bindAff)(HTTPure_Request.fromHTTPRequest(request))(onError500(router)))(HTTPure_Response.send(Effect_Aff.monadEffectAff)(Effect_Aff_Class.monadAffAff)(httpresponse))));
          };
      };
  };
  var serve$prime = function (options) {
      return function (router) {
          return function (onStarted) {
              return function __do() {
                  var server = Node_HTTP.createServer(handleRequest(router))();
                  Node_HTTP.listen(server)(options)(onStarted)();
                  return Node_HTTP.close(server);
              };
          };
      };
  };
  exports["serve'"] = serve$prime;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.Data.Lens"] = $PS["JohnCowie.Data.Lens"] || {};
  var exports = $PS["JohnCowie.Data.Lens"];
  var Control_Semigroupoid = $PS["Control.Semigroupoid"];
  var Data_Function = $PS["Data.Function"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Record = $PS["Record"];                
  var Lens = (function () {
      function Lens(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Lens.create = function (value0) {
          return function (value1) {
              return new Lens(value0, value1);
          };
      };
      return Lens;
  })();
  var Iso = (function () {
      function Iso(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Iso.create = function (value0) {
          return function (value1) {
              return new Iso(value0, value1);
          };
      };
      return Iso;
  })();
  var view = function (v) {
      return function (a) {
          return v.value0(a);
      };
  };
  var set = function (v) {
      return function (b) {
          return function (a) {
              return v.value1(a)(b);
          };
      };
  };
  var over = function (l) {
      return function (f) {
          return function (a) {
              return set(l)(f(view(l)(a)))(a);
          };
      };
  };
  var newtypeIso = function (dictNewtype) {
      return new Iso(Data_Newtype.unwrap(dictNewtype), Data_Newtype.wrap(dictNewtype));
  };
  var lens = Lens.create;
  var prop = function (dictIsSymbol) {
      return function (dictCons) {
          return function (l) {
              return lens(Record.get(dictIsSymbol)()(l))(Data_Function.flip(Record.set(dictIsSymbol)()()(l)));
          };
      };
  };
  var isoToLens = function (v) {
      return lens(v.value0)(Data_Function["const"](v.value1));
  };
  var composeLenses = function (lensCD) {
      return function (lensBC) {
          var setter = function (b) {
              return function (d) {
                  return over(lensBC)(set(lensCD)(d))(b);
              };
          };
          var getter = function (b) {
              return view(lensCD)(view(lensBC)(b));
          };
          return lens(getter)(setter);
      };
  };
  var lensSemigroupoid = new Control_Semigroupoid.Semigroupoid(composeLenses);
  var _newtype = function (dictNewtype) {
      return isoToLens(newtypeIso(dictNewtype));
  };
  exports["view"] = view;
  exports["over"] = over;
  exports["prop"] = prop;
  exports["_newtype"] = _newtype;
  exports["lensSemigroupoid"] = lensSemigroupoid;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.HTTPure"] = $PS["JohnCowie.HTTPure"] || {};
  var exports = $PS["JohnCowie.HTTPure"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Semigroupoid = $PS["Control.Semigroupoid"];
  var Data_Map_Internal = $PS["Data.Map.Internal"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_String_CaseInsensitive = $PS["Data.String.CaseInsensitive"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];
  var HTTPure_Body = $PS["HTTPure.Body"];
  var HTTPure_Headers = $PS["HTTPure.Headers"];
  var HTTPure_Response = $PS["HTTPure.Response"];
  var HTTPure_Server = $PS["HTTPure.Server"];
  var JohnCowie_Data_Lens = $PS["JohnCowie.Data.Lens"];                            
  var BasicRequest = function (x) {
      return x;
  };
  var IsRequest = function (_body, _headers, _httpVersion, _method, _path, _query, _val) {
      this["_body"] = _body;
      this["_headers"] = _headers;
      this["_httpVersion"] = _httpVersion;
      this["_method"] = _method;
      this["_path"] = _path;
      this["_query"] = _query;
      this["_val"] = _val;
  };
  var toCustomRequest = function (v) {
      return {
          headers: v.headers,
          httpVersion: v.httpVersion,
          method: v.method,
          path: v.path,
          query: v.query,
          body: v.body,
          val: Data_Unit.unit
      };
  };
  var response = function (status) {
      return function (body) {
          return {
              headers: HTTPure_Headers.empty,
              status: status,
              body: body
          };
      };
  };
  var newtypeBasicRequest = new Data_Newtype.Newtype(function (n) {
      return n;
  }, BasicRequest);
  var requestBasicRequest = new IsRequest(Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "body";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "headers";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "httpVersion";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "method";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "path";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "query";
  }))()(Data_Symbol.SProxy.value)), Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(JohnCowie_Data_Lens["_newtype"](newtypeBasicRequest))(JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "val";
  }))()(Data_Symbol.SProxy.value)));
  var fromCustomResponse = function (r) {
      return Control_Bind.bind(Effect_Aff.bindAff)(HTTPure_Response.response(Effect_Aff_Class.monadAffAff)(HTTPure_Body.bodyString)(r.status)(r.body))(function (res) {
          return Control_Applicative.pure(Effect_Aff.applicativeAff)({
              headers: r.headers,
              status: res.status,
              writeBody: res.writeBody
          });
      });
  };
  var wrapCustom = function (router) {
      return function (request) {
          return Control_Bind.bind(Effect_Aff.bindAff)(router(toCustomRequest(request)))(function (res) {
              return fromCustomResponse(res);
          });
      };
  };
  var serve$prime = function (options) {
      return function (handler) {
          return function (onStarted) {
              return HTTPure_Server["serve'"](options)(wrapCustom(handler))(onStarted);
          };
      };
  };
  var _responseHeaders = JohnCowie_Data_Lens.prop(new Data_Symbol.IsSymbol(function () {
      return "headers";
  }))()(Data_Symbol.SProxy.value);
  var addResponseHeader = function (k) {
      return function (v) {
          return JohnCowie_Data_Lens.over(Control_Semigroupoid.composeFlipped(JohnCowie_Data_Lens.lensSemigroupoid)(_responseHeaders)(JohnCowie_Data_Lens["_newtype"](HTTPure_Headers.newtypeHeaders)))(Data_Map_Internal.insert(Data_String_CaseInsensitive.ordCaseInsensitiveString)(Data_Newtype.wrap(Data_String_CaseInsensitive.newtypeCaseInsensitiveString)(k))(v));
      };
  };
  var setContentType = addResponseHeader("Content-Type");
  var _path = function (dict) {
      return dict["_path"];
  };
  exports["_path"] = _path;
  exports["response"] = response;
  exports["setContentType"] = setContentType;
  exports["serve'"] = serve$prime;
  exports["requestBasicRequest"] = requestBasicRequest;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Smolder.Markup"] = $PS["Text.Smolder.Markup"] || {};
  var exports = $PS["Text.Smolder.Markup"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Monad_Free = $PS["Control.Monad.Free"];
  var Data_CatList = $PS["Data.CatList"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Unit = $PS["Data.Unit"];                
  var HTMLns = (function () {
      function HTMLns() {

      };
      HTMLns.value = new HTMLns();
      return HTMLns;
  })();
  var SVGns = (function () {
      function SVGns() {

      };
      SVGns.value = new SVGns();
      return SVGns;
  })();
  var Attr = (function () {
      function Attr(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Attr.create = function (value0) {
          return function (value1) {
              return new Attr(value0, value1);
          };
      };
      return Attr;
  })();
  var SafeAttr = (function () {
      function SafeAttr(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      SafeAttr.create = function (value0) {
          return function (value1) {
              return new SafeAttr(value0, value1);
          };
      };
      return SafeAttr;
  })();
  var Attribute = (function () {
      function Attribute(value0) {
          this.value0 = value0;
      };
      Attribute.create = function (value0) {
          return new Attribute(value0);
      };
      return Attribute;
  })();
  var Element = (function () {
      function Element(value0, value1, value2, value3, value4, value5) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
          this.value4 = value4;
          this.value5 = value5;
      };
      Element.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return function (value4) {
                          return function (value5) {
                              return new Element(value0, value1, value2, value3, value4, value5);
                          };
                      };
                  };
              };
          };
      };
      return Element;
  })();
  var Doctype = (function () {
      function Doctype(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Doctype.create = function (value0) {
          return function (value1) {
              return new Doctype(value0, value1);
          };
      };
      return Doctype;
  })();
  var Content = (function () {
      function Content(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Content.create = function (value0) {
          return function (value1) {
              return new Content(value0, value1);
          };
      };
      return Content;
  })();
  var Empty = (function () {
      function Empty(value0) {
          this.value0 = value0;
      };
      Empty.create = function (value0) {
          return new Empty(value0);
      };
      return Empty;
  })();
  var Attributable = function ($$with) {
      this["with"] = $$with;
  };
  var $$with = function (dict) {
      return dict["with"];
  };
  var text = function (s) {
      return Control_Monad_Free.liftF(new Content(s, Data_Unit.unit));
  };
  var parent = function (ns) {
      return function (el) {
          return function (kids) {
              return Control_Monad_Free.liftF(new Element(ns, el, kids, Data_Monoid.mempty(Data_CatList.monoidCatList), Data_Monoid.mempty(Data_CatList.monoidCatList), Data_Unit.unit));
          };
      };
  }; 
  var eqNS = new Data_Eq.Eq(function (x) {
      return function (y) {
          if (x instanceof HTMLns && y instanceof HTMLns) {
              return true;
          };
          if (x instanceof SVGns && y instanceof SVGns) {
              return true;
          };
          return false;
      };
  });
  var attribute = function (key) {
      return function (value) {
          return new Attribute(Control_Applicative.pure(Data_CatList.applicativeCatList)(new Attr(key, value)));
      };
  };
  var attributableMarkup = new Attributable(function (f) {
      return function (v) {
          var withF = function (v1) {
              if (v1 instanceof Element) {
                  return new Element(v1.value0, v1.value1, v1.value2, Data_Semigroup.append(Data_CatList.semigroupCatList)(v1.value3)(v.value0), v1.value4, v1.value5);
              };
              return v1;
          };
          return Control_Monad_Free.hoistFree(withF)(f);
      };
  });
  var attributableMarkupF = new Attributable(function (k) {
      return function (xs) {
          return function (m) {
              return $$with(attributableMarkup)(k(m))(xs);
          };
      };
  });
  exports["Element"] = Element;
  exports["Doctype"] = Doctype;
  exports["Content"] = Content;
  exports["Empty"] = Empty;
  exports["HTMLns"] = HTMLns;
  exports["Attr"] = Attr;
  exports["SafeAttr"] = SafeAttr;
  exports["parent"] = parent;
  exports["text"] = text;
  exports["with"] = $$with;
  exports["attribute"] = attribute;
  exports["eqNS"] = eqNS;
  exports["attributableMarkupF"] = attributableMarkupF;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Smolder.HTML"] = $PS["Text.Smolder.HTML"] || {};
  var exports = $PS["Text.Smolder.HTML"];
  var Text_Smolder_Markup = $PS["Text.Smolder.Markup"];                
  var parent = Text_Smolder_Markup.parent(Text_Smolder_Markup.HTMLns.value);
  var html = parent("html");
  var h1 = parent("h1");
  var div = parent("div");
  var body = parent("body");
  var a = parent("a");
  exports["a"] = a;
  exports["body"] = body;
  exports["div"] = div;
  exports["h1"] = h1;
  exports["html"] = html;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Smolder.HTML.Attributes"] = $PS["Text.Smolder.HTML.Attributes"] || {};
  var exports = $PS["Text.Smolder.HTML.Attributes"];
  var Text_Smolder_Markup = $PS["Text.Smolder.Markup"];    
  var href = Text_Smolder_Markup.attribute("href");
  exports["href"] = href;
})(PS);
(function(exports) {
  /* globals exports, JSON */
  "use strict";                       
  exports.unsafeEncodeURI = encodeURI;
  exports.unsafeDecodeURIComponent = decodeURIComponent;
  exports.unsafeEncodeURIComponent = encodeURIComponent;
})(PS["Global.Unsafe"] = PS["Global.Unsafe"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Global.Unsafe"] = $PS["Global.Unsafe"] || {};
  var exports = $PS["Global.Unsafe"];
  var $foreign = $PS["Global.Unsafe"];
  exports["unsafeEncodeURI"] = $foreign.unsafeEncodeURI;
  exports["unsafeDecodeURIComponent"] = $foreign.unsafeDecodeURIComponent;
  exports["unsafeEncodeURIComponent"] = $foreign.unsafeEncodeURIComponent;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Smolder.Renderer.String"] = $PS["Text.Smolder.Renderer.String"] || {};
  var exports = $PS["Text.Smolder.Renderer.String"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Comonad_Cofree = $PS["Control.Comonad.Cofree"];
  var Control_Extend = $PS["Control.Extend"];
  var Control_Monad_Free = $PS["Control.Monad.Free"];
  var Control_Monad_Rec_Class = $PS["Control.Monad.Rec.Class"];
  var Control_Monad_State = $PS["Control.Monad.State"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Control_Monad_State_Trans = $PS["Control.Monad.State.Trans"];
  var Data_Array = $PS["Data.Array"];
  var Data_Boolean = $PS["Data.Boolean"];
  var Data_CatList = $PS["Data.CatList"];
  var Data_Char = $PS["Data.Char"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_HeytingAlgebra = $PS["Data.HeytingAlgebra"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Map_Internal = $PS["Data.Map.Internal"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Set = $PS["Data.Set"];
  var Data_String_CodePoints = $PS["Data.String.CodePoints"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Global_Unsafe = $PS["Global.Unsafe"];
  var Text_Smolder_Markup = $PS["Text.Smolder.Markup"];                
  var voidElements = Data_Set.fromFoldable(Data_Foldable.foldableArray)(Data_Ord.ordString)([ "area", "base", "br", "col", "command", "embed", "hr", "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr" ]);
  var toStream = function (s) {
      var cs = Data_String_CodeUnits.toCharArray(s);
      return Data_Foldable.foldr(Data_Foldable.foldableArray)(function (c) {
          return function (t) {
              return Control_Comonad_Cofree.mkCofree(c)(new Data_Maybe.Just(t));
          };
      })(Control_Comonad_Cofree.mkCofree("\x00")(Data_Maybe.Nothing.value))(cs);
  };
  var isURLAttr = function (tag) {
      return function (attr) {
          if (attr === "href" && tag === "a") {
              return true;
          };
          if (attr === "href" && tag === "area") {
              return true;
          };
          if (attr === "href" && tag === "base") {
              return true;
          };
          if (attr === "href" && tag === "link") {
              return true;
          };
          if (attr === "src" && tag === "audio") {
              return true;
          };
          if (attr === "src" && tag === "embed") {
              return true;
          };
          if (attr === "src" && tag === "iframe") {
              return true;
          };
          if (attr === "src" && tag === "img") {
              return true;
          };
          if (attr === "src" && tag === "input") {
              return true;
          };
          if (attr === "src" && tag === "script") {
              return true;
          };
          if (attr === "src" && tag === "source") {
              return true;
          };
          if (attr === "src" && tag === "track") {
              return true;
          };
          if (attr === "src" && tag === "video") {
              return true;
          };
          if (attr === "code" && tag === "applet") {
              return true;
          };
          if (attr === "codebase" && tag === "applet") {
              return true;
          };
          if (attr === "data" && tag === "object") {
              return true;
          };
          if (attr === "manifest" && tag === "html") {
              return true;
          };
          if (attr === "poster" && tag === "video") {
              return true;
          };
          if (Data_Boolean.otherwise) {
              return false;
          };
          throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 75, column 1 - line 75, column 41): " + [ tag.constructor.name, attr.constructor.name ]);
      };
  };
  var isMIMEAttr = function (tag) {
      return function (attr) {
          if (attr === "type" && tag === "embed") {
              return true;
          };
          if (attr === "type" && tag === "object") {
              return true;
          };
          if (attr === "type" && tag === "script") {
              return true;
          };
          if (attr === "type" && tag === "source") {
              return true;
          };
          if (attr === "type" && tag === "style") {
              return true;
          };
          if (Data_Boolean.otherwise) {
              return false;
          };
          throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 64, column 1 - line 64, column 42): " + [ tag.constructor.name, attr.constructor.name ]);
      };
  };
  var fromStream = (function () {
      var go = function ($copy_result) {
          return function ($copy_cof) {
              var $tco_var_result = $copy_result;
              var $tco_done = false;
              var $tco_result;
              function $tco_loop(result, cof) {
                  var v = Control_Comonad_Cofree.tail(cof);
                  var v1 = Control_Comonad_Cofree.head(cof);
                  if (v instanceof Data_Maybe.Nothing) {
                      $tco_done = true;
                      return result;
                  };
                  if (v instanceof Data_Maybe.Just) {
                      $tco_var_result = result + v1;
                      $copy_cof = v.value0;
                      return;
                  };
                  throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 107, column 7 - line 109, column 48): " + [ v1.constructor.name, v.constructor.name ]);
              };
              while (!$tco_done) {
                  $tco_result = $tco_loop($tco_var_result, $copy_cof);
              };
              return $tco_result;
          };
      };
      return go("");
  })();
  var escapeMap = Data_Map_Internal.fromFoldable(Data_Ord.ordChar)(Data_Foldable.foldableArray)([ new Data_Tuple.Tuple("&", "&amp;"), new Data_Tuple.Tuple("<", "&lt;"), new Data_Tuple.Tuple(">", "&gt;"), new Data_Tuple.Tuple("\"", "&quot;"), new Data_Tuple.Tuple("'", "&#39;"), new Data_Tuple.Tuple("/", "&#x2F;") ]);
  var escapeMIMEMap = Data_Map_Internal.fromFoldable(Data_Ord.ordChar)(Data_Foldable.foldableArray)([ new Data_Tuple.Tuple("&", "&amp;"), new Data_Tuple.Tuple("<", "&lt;"), new Data_Tuple.Tuple("\"", "&quot;"), new Data_Tuple.Tuple("'", "&#39;") ]);
  var $$escape = function (m) {
      var checkTail = function (allowed) {
          var checkTail$prime = function (w) {
              var v = Data_Char.toCharCode(Control_Comonad_Cofree.head(w));
              if (Data_Foldable.elem(Data_Foldable.foldableArray)(Data_Eq.eqInt)(v)(allowed)) {
                  return Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_State_Trans.bindStateT(Data_Identity.monadIdentity))(Control_Monad_State_Class.put(Control_Monad_State_Trans.monadStateStateT(Data_Identity.monadIdentity))(true))(function () {
                      return Data_Maybe.fromMaybe(Control_Applicative.pure(Control_Monad_State_Trans.applicativeStateT(Data_Identity.monadIdentity))(false))(Data_Functor.map(Data_Maybe.functorMaybe)(checkTail$prime)(Control_Comonad_Cofree.tail(w)));
                  });
              };
              if (v === 59) {
                  return Control_Monad_State_Class.get(Control_Monad_State_Trans.monadStateStateT(Data_Identity.monadIdentity));
              };
              if (Data_Boolean.otherwise) {
                  return Control_Applicative.pure(Control_Monad_State_Trans.applicativeStateT(Data_Identity.monadIdentity))(false);
              };
              throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 128, column 11 - line 133, column 42): " + [ v.constructor.name ]);
          };
          var $44 = Data_Function.flip(Control_Monad_State.evalState)(false);
          return function ($45) {
              return $44(checkTail$prime($45));
          };
      };
      var startsEntity = function (v) {
          if (v instanceof Data_Maybe.Just) {
              var v1 = Control_Comonad_Cofree.tail(v.value0);
              var v2 = Control_Comonad_Cofree.head(v.value0);
              if (v2 === "#" && v1 instanceof Data_Maybe.Just) {
                  return checkTail(Data_Array.range(48)(57))(v1.value0);
              };
              if (v2 === "#" && v1 instanceof Data_Maybe.Nothing) {
                  return false;
              };
              return checkTail(Data_Semigroup.append(Data_Semigroup.semigroupArray)(Data_Array.range(65)(90))(Data_Array.range(97)(122)))(v.value0);
          };
          if (v instanceof Data_Maybe.Nothing) {
              return false;
          };
          throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 114, column 5 - line 114, column 57): " + [ v.constructor.name ]);
      };
      var escapeS = function (w) {
          var v = Control_Comonad_Cofree.head(w);
          if (v === "&") {
              if (startsEntity(Control_Comonad_Cofree.tail(w))) {
                  return "&";
              };
              if (Data_Boolean.otherwise) {
                  return "&amp;";
              };
          };
          return Data_Maybe.fromMaybe(Data_String_CodeUnits.fromCharArray([ v ]))(Data_Map_Internal.lookup(Data_Ord.ordChar)(v)(m));
      };
      var $46 = Control_Extend.extend(Control_Comonad_Cofree.extendCofree(Data_Maybe.functorMaybe))(escapeS);
      return function ($47) {
          return fromStream($46(toStream($47)));
      };
  };
  var escapeAttrValue = function (tag) {
      return function (key) {
          return function (value) {
              if (isURLAttr(tag)(key)) {
                  return Global_Unsafe.unsafeEncodeURI(value);
              };
              if (isMIMEAttr(tag)(key)) {
                  return $$escape(escapeMIMEMap)(value);
              };
              if (Data_Boolean.otherwise) {
                  return $$escape(escapeMap)(value);
              };
              throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 142, column 1 - line 142, column 56): " + [ tag.constructor.name, key.constructor.name, value.constructor.name ]);
          };
      };
  };
  var showAttrs = function (tag) {
      var showAttr = function (v) {
          if (v instanceof Text_Smolder_Markup.SafeAttr) {
              return " " + (v.value0 + ("=\"" + (v.value1 + "\"")));
          };
          if (v instanceof Text_Smolder_Markup.Attr) {
              return " " + (v.value0 + ("=\"" + (escapeAttrValue(tag)(v.value0)(v.value1) + "\"")));
          };
          throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 151, column 5 - line 151, column 73): " + [ v.constructor.name ]);
      };
      var $48 = Data_Foldable.fold(Data_CatList.foldableCatList)(Data_Monoid.monoidString);
      var $49 = Data_Functor.map(Data_CatList.functorCatList)(showAttr);
      return function ($50) {
          return $48($49($50));
      };
  };
  var renderItem = function (v) {
      if (v instanceof Text_Smolder_Markup.Element) {
          var c = render(v.value2);
          var b = "<" + (v.value1 + (showAttrs(v.value1)(v.value3) + (function () {
              var $32 = Data_String_CodePoints.length(c) > 0 || Data_Eq.eq(Text_Smolder_Markup.eqNS)(v.value0)(Text_Smolder_Markup.HTMLns.value) && Data_HeytingAlgebra.not(Data_HeytingAlgebra.heytingAlgebraFunction(Data_HeytingAlgebra.heytingAlgebraFunction(Data_HeytingAlgebra.heytingAlgebraBoolean)))(Data_Set.member(Data_Ord.ordString))(v.value1)(voidElements);
              if ($32) {
                  return ">" + (c + ("</" + (v.value1 + ">")));
              };
              return "/>";
          })()));
          return Control_Monad_State_Class.state(Control_Monad_State_Trans.monadStateStateT(Data_Identity.monadIdentity))(function (s) {
              return Data_Tuple.Tuple.create(v.value5)(s + b);
          });
      };
      if (v instanceof Text_Smolder_Markup.Content) {
          return Control_Monad_State_Class.state(Control_Monad_State_Trans.monadStateStateT(Data_Identity.monadIdentity))(function (s) {
              return Data_Tuple.Tuple.create(v.value1)(s + $$escape(escapeMap)(v.value0));
          });
      };
      if (v instanceof Text_Smolder_Markup.Doctype) {
          return Control_Monad_State_Class.state(Control_Monad_State_Trans.monadStateStateT(Data_Identity.monadIdentity))(function (s) {
              return Data_Tuple.Tuple.create(v.value1)(s + ("<!DOCTYPE " + (v.value0 + ">")));
          });
      };
      if (v instanceof Text_Smolder_Markup.Empty) {
          return Control_Applicative.pure(Control_Monad_State_Trans.applicativeStateT(Data_Identity.monadIdentity))(v.value0);
      };
      throw new Error("Failed pattern match at Text.Smolder.Renderer.String (line 158, column 1 - line 158, column 45): " + [ v.constructor.name ]);
  };
  var render = function (f) {
      return Control_Monad_State.execState(Control_Monad_Free.foldFree(Control_Monad_State_Trans.monadRecStateT(Control_Monad_Rec_Class.monadRecIdentity))(renderItem)(f))("");
  };
  exports["render"] = render;
})(PS);
(function($PS) {
  "use strict";
  $PS["Fundoscopic.Handlers"] = $PS["Fundoscopic.Handlers"] || {};
  var exports = $PS["Fundoscopic.Handlers"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Free = $PS["Control.Monad.Free"];
  var JohnCowie_HTTPure = $PS["JohnCowie.HTTPure"];
  var Text_Smolder_HTML = $PS["Text.Smolder.HTML"];
  var Text_Smolder_HTML_Attributes = $PS["Text.Smolder.HTML.Attributes"];
  var Text_Smolder_Markup = $PS["Text.Smolder.Markup"];
  var Text_Smolder_Renderer_String = $PS["Text.Smolder.Renderer.String"];
  var htmlResponse = function (status) {
      var $9 = JohnCowie_HTTPure.setContentType("text/html");
      var $10 = JohnCowie_HTTPure.response(status);
      return function ($11) {
          return $9($10(Text_Smolder_Renderer_String.render($11)));
      };
  };
  var login = function (dictMonad) {
      return function (oauth) {
          return function (v) {
              return Control_Applicative.pure(dictMonad.Applicative0())(htmlResponse(200)(Text_Smolder_HTML.html(Text_Smolder_HTML.body(Text_Smolder_HTML.div(Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Free.freeBind)(Text_Smolder_HTML.h1(Text_Smolder_Markup.text("Login")))(function () {
                  return Text_Smolder_Markup["with"](Text_Smolder_Markup.attributableMarkupF)(Text_Smolder_HTML.a)(Text_Smolder_HTML_Attributes.href(oauth.redirect))(Text_Smolder_Markup.text("Login"));
              }))))));
          };
      };
  };
  var notFound = function (dictMonad) {
      return function (v) {
          return Control_Applicative.pure(dictMonad.Applicative0())(htmlResponse(404)(Text_Smolder_HTML.html(Text_Smolder_HTML.body(Text_Smolder_HTML.div(Text_Smolder_HTML.h1(Text_Smolder_Markup.text("Not Found")))))));
      };
  };
  var home = function (dictMonad) {
      return function (v) {
          return Control_Applicative.pure(dictMonad.Applicative0())(htmlResponse(200)(Text_Smolder_HTML.html(Text_Smolder_HTML.body(Text_Smolder_HTML.div(Text_Smolder_HTML.h1(Text_Smolder_Markup.text("Hello Fundoscopic World!!!")))))));
      };
  };
  exports["notFound"] = notFound;
  exports["home"] = home;
  exports["login"] = login;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Fundoscopic.Migrations"] = $PS["Fundoscopic.Migrations"] || {};
  var exports = $PS["Fundoscopic.Migrations"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Data_Either = $PS["Data.Either"];
  var createOAuthUserTable = function (id) {
      return {
          id: id,
          up: "\x0a              CREATE TABLE IF NOT EXISTS users (\x0a                id SERIAL PRIMARY KEY\x0a              , google_id VARCHAR NOT NULL\x0a              , name VARCHAR\x0a              , access_token VARCHAR NOT NULL\x0a              , UNIQUE(google_id)\x0a              );\x0a        ",
          down: "\x0a          DROP TABLE IF EXISTS users;\x0a        ",
          description: ""
      };
  };
  var migrations = [ createOAuthUserTable(1) ];
  var migrationStore = function (dictMonad) {
      return {
          loadMigrations: Control_Applicative.pure(dictMonad.Applicative0())(Control_Applicative.pure(Data_Either.applicativeEither)(migrations))
      };
  };
  exports["migrationStore"] = migrationStore;
})(PS);
(function($PS) {
  "use strict";
  $PS["Fundoscopic.Routing"] = $PS["Fundoscopic.Routing"] || {};
  var exports = $PS["Fundoscopic.Routing"];
  var Data_Maybe = $PS["Data.Maybe"];                                

  // type Routes = BiMap HandlerId (Array String)
  var Home = (function () {
      function Home() {

      };
      Home.value = new Home();
      return Home;
  })();

  // type Routes = BiMap HandlerId (Array String)
  var Login = (function () {
      function Login() {

      };
      Login.value = new Login();
      return Login;
  })();
  var handlerIdForPath = function (v) {
      if (v.length === 1 && v[0] === "login") {
          return new Data_Maybe.Just(Login.value);
      };
      if (v.length === 0) {
          return new Data_Maybe.Just(Home.value);
      };
      return Data_Maybe.Nothing.value;
  };
  exports["Home"] = Home;
  exports["Login"] = Login;
  exports["handlerIdForPath"] = handlerIdForPath;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.JWT"] = $PS["JohnCowie.JWT"] || {};
  var exports = $PS["JohnCowie.JWT"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Argonaut_Decode_Class = $PS["Data.Argonaut.Decode.Class"];
  var Data_Argonaut_Decode_Error = $PS["Data.Argonaut.Decode.Error"];
  var Data_Argonaut_Parser = $PS["Data.Argonaut.Parser"];
  var Data_Array = $PS["Data.Array"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_Base64 = $PS["Data.String.Base64"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Effect_Exception = $PS["Effect.Exception"];                
  var JWT = function (x) {
      return x;
  };
  var newtypeJWT = new Data_Newtype.Newtype(function (n) {
      return n;
  }, JWT);
  var extractPayload = function (dictDecodeJson) {
      return function (v) {
          var parts = Data_String_Common.split(".")(v);
          return Control_Bind.bind(Data_Either.bindEither)(Data_Maybe.maybe(new Data_Either.Left("No second part of token"))(Data_Either.Right.create)(Data_Array.index(parts)(1)))(function (part) {
              return Control_Bind.bind(Data_Either.bindEither)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Effect_Exception.showError))(Data_String_Base64.decode(part)))(function (jsonStr) {
                  return Control_Bind.bind(Data_Either.bindEither)(Data_Argonaut_Parser.jsonParser(jsonStr))(function (json) {
                      return Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Argonaut_Decode_Error.printJsonDecodeError)(Data_Argonaut_Decode_Class.decodeJson(dictDecodeJson)(json));
                  });
              });
          });
      };
  };    
  var decodeJsonJWT = new Data_Argonaut_Decode_Class.DecodeJson((function () {
      var $19 = Data_Functor.map(Data_Either.functorEither)(Data_Newtype.wrap(newtypeJWT));
      var $20 = Data_Argonaut_Decode_Class.decodeJson(Data_Argonaut_Decode_Class.decodeJsonString);
      return function ($21) {
          return $19($20($21));
      };
  })());
  exports["extractPayload"] = extractPayload;
  exports["decodeJsonJWT"] = decodeJsonJWT;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.Migrations"] = $PS["JohnCowie.Migrations"] || {};
  var exports = $PS["JohnCowie.Migrations"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Array = $PS["Data.Array"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Show = $PS["Data.Show"];
  var Data_Traversable = $PS["Data.Traversable"];
  var runMigration = function (dictMonad) {
      return function (v) {
          return function (migration) {
              return Control_Monad_Except_Trans.runExceptT(Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(dictMonad))(Control_Monad_Except_Trans.ExceptT(v.executor.executeMigration(migration.id)(migration.up)))(function () {
                  return Control_Monad_Except_Trans.ExceptT(v.versionStore.updateVersion(true)(migration));
              }));
          };
      };
  };
  var remainingMigrations = function (dictOrd) {
      return function (v) {
          return function (migrations) {
              if (v instanceof Data_Maybe.Nothing) {
                  return migrations;
              };
              if (v instanceof Data_Maybe.Just) {
                  return Data_Array.dropWhile(function (r) {
                      return Data_Ord.lessThanOrEq(dictOrd)(r.id)(v.value0);
                  })(Data_Array.sortWith(dictOrd)(function (v1) {
                      return v1.id;
                  })(migrations));
              };
              throw new Error("Failed pattern match at JohnCowie.Migrations (line 37, column 1 - line 37, column 111): " + [ v.constructor.name, migrations.constructor.name ]);
          };
      };
  };
  var migrationIds = Data_Functor.map(Data_Functor.functorArray)(function (v) {
      return v.id;
  });
  var migrate = function (dictShow) {
      return function (dictOrd) {
          return function (dictMonad) {
              return function (v) {
                  return Control_Monad_Except_Trans.runExceptT(Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(dictMonad))(v.migrationStore.loadMigrations)(function (migrations) {
                      return Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(dictMonad))(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(((dictMonad.Bind1()).Apply0()).Functor0())(Data_Either.Right.create)(v.logger("MIGRATION IDS: " + Data_Show.show(Data_Show.showArray(dictShow))(migrationIds(migrations))))))(function () {
                          return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(dictMonad))(v.versionStore.currentVersion)(function (currentVersion) {
                              return Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(dictMonad))(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(((dictMonad.Bind1()).Apply0()).Functor0())(Data_Either.Right.create)(v.logger("CURRENT VERSION: " + Data_Show.show(Data_Maybe.showMaybe(dictShow))(currentVersion)))))(function () {
                                  return Data_Functor["void"](Control_Monad_Except_Trans.functorExceptT(((dictMonad.Bind1()).Apply0()).Functor0()))(Data_Traversable["for"](Control_Monad_Except_Trans.applicativeExceptT(dictMonad))(Data_Traversable.traversableArray)(remainingMigrations(dictOrd)(currentVersion)(migrations))((function () {
                                      var $44 = runMigration(dictMonad)(v);
                                      return function ($45) {
                                          return Control_Monad_Except_Trans.ExceptT($44($45));
                                      };
                                  })()));
                              });
                          });
                      });
                  }));
              };
          };
      };
  };
  exports["migrate"] = migrate;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.OAuth"] = $PS["JohnCowie.OAuth"] || {};
  var exports = $PS["JohnCowie.OAuth"];
  var Data_Newtype = $PS["Data.Newtype"];                                                  
  var OAuthCode = function (x) {
      return x;
  };
  var newtypeOAuthCode = new Data_Newtype.Newtype(function (n) {
      return n;
  }, OAuthCode);
  exports["newtypeOAuthCode"] = newtypeOAuthCode;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Parsing.Parser.Pos"] = $PS["Text.Parsing.Parser.Pos"] || {};
  var exports = $PS["Text.Parsing.Parser.Pos"];
  var Data_EuclideanRing = $PS["Data.EuclideanRing"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_String_Pattern = $PS["Data.String.Pattern"];
  var updatePosString = function (pos$prime) {
      return function (str) {
          var updatePosChar = function (v) {
              return function (c) {
                  if (c === "\x0a") {
                      return {
                          line: v.line + 1 | 0,
                          column: 1
                      };
                  };
                  if (c === "\x0d") {
                      return {
                          line: v.line + 1 | 0,
                          column: 1
                      };
                  };
                  if (c === "\x09") {
                      return {
                          line: v.line,
                          column: (v.column + 8 | 0) - Data_EuclideanRing.mod(Data_EuclideanRing.euclideanRingInt)(v.column - 1 | 0)(8) | 0
                      };
                  };
                  return {
                      line: v.line,
                      column: v.column + 1 | 0
                  };
              };
          };
          return Data_Foldable.foldl(Data_Foldable.foldableArray)(updatePosChar)(pos$prime)(Data_String_Common.split(Data_Newtype.wrap(Data_String_Pattern.newtypePattern)(""))(str));
      };
  };
  var showPosition = new Data_Show.Show(function (v) {
      return "(Position { line: " + (Data_Show.show(Data_Show.showInt)(v.line) + (", column: " + (Data_Show.show(Data_Show.showInt)(v.column) + " })")));
  });
  var initialPos = {
      line: 1,
      column: 1
  };
  exports["initialPos"] = initialPos;
  exports["updatePosString"] = updatePosString;
  exports["showPosition"] = showPosition;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Parsing.Parser"] = $PS["Text.Parsing.Parser"] || {};
  var exports = $PS["Text.Parsing.Parser"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Alternative = $PS["Control.Alternative"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Lazy = $PS["Control.Lazy"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Control_Monad_State_Trans = $PS["Control.Monad.State.Trans"];
  var Control_Plus = $PS["Control.Plus"];
  var Data_Either = $PS["Data.Either"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Show = $PS["Data.Show"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Text_Parsing_Parser_Pos = $PS["Text.Parsing.Parser.Pos"];                
  var ParseState = (function () {
      function ParseState(value0, value1, value2) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
      };
      ParseState.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return new ParseState(value0, value1, value2);
              };
          };
      };
      return ParseState;
  })();
  var ParseError = (function () {
      function ParseError(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      ParseError.create = function (value0) {
          return function (value1) {
              return new ParseError(value0, value1);
          };
      };
      return ParseError;
  })();
  var ParserT = function (x) {
      return x;
  };
  var showParseError = new Data_Show.Show(function (v) {
      return "(ParseError " + (Data_Show.show(Data_Show.showString)(v.value0) + (" " + (Data_Show.show(Text_Parsing_Parser_Pos.showPosition)(v.value1) + ")")));
  });
  var newtypeParserT = new Data_Newtype.Newtype(function (n) {
      return n;
  }, ParserT);
  var runParserT = function (dictMonad) {
      return function (s) {
          return function (p) {
              var initialState = new ParseState(s, Text_Parsing_Parser_Pos.initialPos, false);
              return Control_Monad_State_Trans.evalStateT(((dictMonad.Bind1()).Apply0()).Functor0())(Control_Monad_Except_Trans.runExceptT(Data_Newtype.unwrap(newtypeParserT)(p)))(initialState);
          };
      };
  };
  var runParser = function (s) {
      var $90 = Data_Newtype.unwrap(Data_Identity.newtypeIdentity);
      var $91 = runParserT(Data_Identity.monadIdentity)(s);
      return function ($92) {
          return $90($91($92));
      };
  }; 
  var monadThrowParserT = function (dictMonad) {
      return Control_Monad_Except_Trans.monadThrowExceptT(Control_Monad_State_Trans.monadStateT(dictMonad));
  };
  var monadStateParserT = function (dictMonad) {
      return Control_Monad_Except_Trans.monadStateExceptT(Control_Monad_State_Trans.monadStateStateT(dictMonad));
  };
  var position = function (dictMonad) {
      return Control_Monad_State_Class.gets(monadStateParserT(dictMonad))(function (v) {
          return v.value1;
      });
  };   
  var lazyParserT = new Control_Lazy.Lazy(function (f) {
      return Control_Lazy.defer(Control_Monad_State_Trans.lazyStateT)((function () {
          var $98 = Data_Newtype.unwrap(newtypeParserT);
          return function ($99) {
              return Control_Monad_Except_Trans.runExceptT($98(f($99)));
          };
      })());
  });                           
  var functorParserT = function (dictFunctor) {
      return Control_Monad_Except_Trans.functorExceptT(Control_Monad_State_Trans.functorStateT(dictFunctor));
  };
  var failWithPosition = function (dictMonad) {
      return function (message) {
          return function (pos) {
              return Control_Monad_Error_Class.throwError(monadThrowParserT(dictMonad))(new ParseError(message, pos));
          };
      };
  };
  var bindParserT = function (dictMonad) {
      return Control_Monad_Except_Trans.bindExceptT(Control_Monad_State_Trans.monadStateT(dictMonad));
  };
  var fail = function (dictMonad) {
      return function (message) {
          return Control_Bind.bindFlipped(bindParserT(dictMonad))(failWithPosition(dictMonad)(message))(position(dictMonad));
      };
  };
  var applyParserT = function (dictMonad) {
      return Control_Monad_Except_Trans.applyExceptT(Control_Monad_State_Trans.monadStateT(dictMonad));
  };
  var applicativeParserT = function (dictMonad) {
      return Control_Monad_Except_Trans.applicativeExceptT(Control_Monad_State_Trans.monadStateT(dictMonad));
  };
  var altParserT = function (dictMonad) {
      return new Control_Alt.Alt(function () {
          return functorParserT(((dictMonad.Bind1()).Apply0()).Functor0());
      }, function (p1) {
          return function (p2) {
              return ParserT(Control_Monad_Except_Trans.ExceptT(Control_Monad_State_Trans.StateT(function (v) {
                  return Control_Bind.bind(dictMonad.Bind1())(Control_Monad_State_Trans.runStateT(Control_Monad_Except_Trans.runExceptT(Data_Newtype.unwrap(newtypeParserT)(p1)))(new ParseState(v.value0, v.value1, false)))(function (v1) {
                      if (v1.value0 instanceof Data_Either.Left && !v1.value1.value2) {
                          return Control_Monad_State_Trans.runStateT(Control_Monad_Except_Trans.runExceptT(Data_Newtype.unwrap(newtypeParserT)(p2)))(v);
                      };
                      return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(v1.value0, v1.value1));
                  });
              })));
          };
      });
  };
  var plusParserT = function (dictMonad) {
      return new Control_Plus.Plus(function () {
          return altParserT(dictMonad);
      }, fail(dictMonad)("No alternative"));
  };
  var alternativeParserT = function (dictMonad) {
      return new Control_Alternative.Alternative(function () {
          return applicativeParserT(dictMonad);
      }, function () {
          return plusParserT(dictMonad);
      });
  };
  exports["ParseError"] = ParseError;
  exports["ParseState"] = ParseState;
  exports["ParserT"] = ParserT;
  exports["runParser"] = runParser;
  exports["fail"] = fail;
  exports["showParseError"] = showParseError;
  exports["newtypeParserT"] = newtypeParserT;
  exports["lazyParserT"] = lazyParserT;
  exports["functorParserT"] = functorParserT;
  exports["applyParserT"] = applyParserT;
  exports["applicativeParserT"] = applicativeParserT;
  exports["bindParserT"] = bindParserT;
  exports["monadStateParserT"] = monadStateParserT;
  exports["altParserT"] = altParserT;
  exports["alternativeParserT"] = alternativeParserT;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Parsing.Parser.Combinators"] = $PS["Text.Parsing.Parser.Combinators"] || {};
  var exports = $PS["Text.Parsing.Parser.Combinators"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Control_Monad_State_Trans = $PS["Control.Monad.State.Trans"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];                
  var withErrorMessage = function (dictMonad) {
      return function (p) {
          return function (msg) {
              return Control_Alt.alt(Text_Parsing_Parser.altParserT(dictMonad))(p)(Text_Parsing_Parser.fail(dictMonad)("Expected " + msg));
          };
      };
  };
  var tryRethrow = function (dictMonad) {
      return function (p) {
          return Text_Parsing_Parser.ParserT(Control_Monad_Except_Trans.ExceptT(Control_Monad_State_Trans.StateT(function (v) {
              return Control_Bind.bind(dictMonad.Bind1())(Control_Monad_State_Trans.runStateT(Control_Monad_Except_Trans.runExceptT(Data_Newtype.unwrap(Text_Parsing_Parser.newtypeParserT)(p)))(v))(function (v1) {
                  if (v1.value0 instanceof Data_Either.Left) {
                      return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(new Data_Either.Left(new Text_Parsing_Parser.ParseError(v1.value0.value0.value0, v.value1)), new Text_Parsing_Parser.ParseState(v1.value1.value0, v1.value1.value1, v.value2)));
                  };
                  return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(v1.value0, v1.value1));
              });
          })));
      };
  };
  var $$try = function (dictMonad) {
      return function (p) {
          return Text_Parsing_Parser.ParserT(Control_Monad_Except_Trans.ExceptT(Control_Monad_State_Trans.StateT(function (v) {
              return Control_Bind.bind(dictMonad.Bind1())(Control_Monad_State_Trans.runStateT(Control_Monad_Except_Trans.runExceptT(Data_Newtype.unwrap(Text_Parsing_Parser.newtypeParserT)(p)))(v))(function (v1) {
                  if (v1.value0 instanceof Data_Either.Left) {
                      return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(v1.value0, new Text_Parsing_Parser.ParseState(v1.value1.value0, v1.value1.value1, v.value2)));
                  };
                  return Control_Applicative.pure(dictMonad.Applicative0())(new Data_Tuple.Tuple(v1.value0, v1.value1));
              });
          })));
      };
  };
  var option = function (dictMonad) {
      return function (a) {
          return function (p) {
              return Control_Alt.alt(Text_Parsing_Parser.altParserT(dictMonad))(p)(Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(dictMonad))(a));
          };
      };
  };
  var optionMaybe = function (dictMonad) {
      return function (p) {
          return option(dictMonad)(Data_Maybe.Nothing.value)(Data_Functor.map(Text_Parsing_Parser.functorParserT(((dictMonad.Bind1()).Apply0()).Functor0()))(Data_Maybe.Just.create)(p));
      };
  };
  exports["withErrorMessage"] = withErrorMessage;
  exports["optionMaybe"] = optionMaybe;
  exports["try"] = $$try;
  exports["tryRethrow"] = tryRethrow;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Parsing.Parser.String"] = $PS["Text.Parsing.Parser.String"] || {};
  var exports = $PS["Text.Parsing.Parser.String"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Data_Eq = $PS["Data.Eq"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Function = $PS["Data.Function"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_CodePoints = $PS["Data.String.CodePoints"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_String_Pattern = $PS["Data.String.Pattern"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_Pos = $PS["Text.Parsing.Parser.Pos"];                
  var StringLike = function (drop, indexOf, $$null, uncons) {
      this.drop = drop;
      this.indexOf = indexOf;
      this["null"] = $$null;
      this.uncons = uncons;
  };
  var uncons = function (dict) {
      return dict.uncons;
  };
  var stringLikeString = new StringLike(Data_String_CodePoints.drop, Data_String_CodePoints.indexOf, Data_String_Common["null"], Data_String_CodeUnits.uncons);
  var $$null = function (dict) {
      return dict["null"];
  };
  var indexOf = function (dict) {
      return dict.indexOf;
  };
  var eof = function (dictStringLike) {
      return function (dictMonad) {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(dictMonad))(Control_Monad_State_Class.gets(Text_Parsing_Parser.monadStateParserT(dictMonad))(function (v) {
              return v.value0;
          }))(function (input) {
              return Control_Applicative.unless(Text_Parsing_Parser.applicativeParserT(dictMonad))($$null(dictStringLike)(input))(Text_Parsing_Parser.fail(dictMonad)("Expected EOF"));
          });
      };
  };
  var drop = function (dict) {
      return dict.drop;
  };
  var string = function (dictStringLike) {
      return function (dictMonad) {
          return function (str) {
              return Control_Bind.bind(Text_Parsing_Parser.bindParserT(dictMonad))(Control_Monad_State_Class.gets(Text_Parsing_Parser.monadStateParserT(dictMonad))(function (v) {
                  return v.value0;
              }))(function (input) {
                  var v = indexOf(dictStringLike)(Data_Newtype.wrap(Data_String_Pattern.newtypePattern)(str))(input);
                  if (v instanceof Data_Maybe.Just && v.value0 === 0) {
                      return Control_Bind.discard(Control_Bind.discardUnit)(Text_Parsing_Parser.bindParserT(dictMonad))(Control_Monad_State_Class.modify_(Text_Parsing_Parser.monadStateParserT(dictMonad))(function (v1) {
                          return new Text_Parsing_Parser.ParseState(drop(dictStringLike)(Data_String_CodePoints.length(str))(input), Text_Parsing_Parser_Pos.updatePosString(v1.value1)(str), true);
                      }))(function () {
                          return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(dictMonad))(str);
                      });
                  };
                  return Text_Parsing_Parser.fail(dictMonad)("Expected " + Data_Show.show(Data_Show.showString)(str));
              });
          };
      };
  };
  var anyChar = function (dictStringLike) {
      return function (dictMonad) {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(dictMonad))(Control_Monad_State_Class.gets(Text_Parsing_Parser.monadStateParserT(dictMonad))(function (v) {
              return v.value0;
          }))(function (input) {
              var v = uncons(dictStringLike)(input);
              if (v instanceof Data_Maybe.Nothing) {
                  return Text_Parsing_Parser.fail(dictMonad)("Unexpected EOF");
              };
              if (v instanceof Data_Maybe.Just) {
                  return Control_Bind.discard(Control_Bind.discardUnit)(Text_Parsing_Parser.bindParserT(dictMonad))(Control_Monad_State_Class.modify_(Text_Parsing_Parser.monadStateParserT(dictMonad))(function (v1) {
                      return new Text_Parsing_Parser.ParseState(v.value0.tail, Text_Parsing_Parser_Pos.updatePosString(v1.value1)(Data_String_CodeUnits.singleton(v.value0.head)), true);
                  }))(function () {
                      return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(dictMonad))(v.value0.head);
                  });
              };
              throw new Error("Failed pattern match at Text.Parsing.Parser.String (line 56, column 3 - line 63, column 16): " + [ v.constructor.name ]);
          });
      };
  };
  var satisfy = function (dictStringLike) {
      return function (dictMonad) {
          return function (f) {
              return Text_Parsing_Parser_Combinators.tryRethrow(dictMonad)(Control_Bind.bind(Text_Parsing_Parser.bindParserT(dictMonad))(anyChar(dictStringLike)(dictMonad))(function (c) {
                  var $52 = f(c);
                  if ($52) {
                      return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(dictMonad))(c);
                  };
                  return Text_Parsing_Parser.fail(dictMonad)("Character '" + (Data_String_CodeUnits.singleton(c) + "' did not satisfy predicate"));
              }));
          };
      };
  };
  var $$char = function (dictStringLike) {
      return function (dictMonad) {
          return function (c) {
              return Text_Parsing_Parser_Combinators.withErrorMessage(dictMonad)(satisfy(dictStringLike)(dictMonad)(function (v) {
                  return v === c;
              }))(Data_Show.show(Data_Show.showChar)(c));
          };
      };
  };
  var oneOf = function (dictStringLike) {
      return function (dictMonad) {
          return function (ss) {
              return Text_Parsing_Parser_Combinators.withErrorMessage(dictMonad)(satisfy(dictStringLike)(dictMonad)(Data_Function.flip(Data_Foldable.elem(Data_Foldable.foldableArray)(Data_Eq.eqChar))(ss)))("one of " + Data_Show.show(Data_Show.showArray(Data_Show.showChar))(ss));
          };
      };
  };
  exports["eof"] = eof;
  exports["string"] = string;
  exports["anyChar"] = anyChar;
  exports["satisfy"] = satisfy;
  exports["char"] = $$char;
  exports["oneOf"] = oneOf;
  exports["stringLikeString"] = stringLikeString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Text.Parsing.Parser.Token"] = $PS["Text.Parsing.Parser.Token"] || {};
  var exports = $PS["Text.Parsing.Parser.Token"];
  var Data_Char_Unicode = $PS["Data.Char.Unicode"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var hexDigit = function (dictMonad) {
      return Text_Parsing_Parser_Combinators.withErrorMessage(dictMonad)(Text_Parsing_Parser_String.satisfy(Text_Parsing_Parser_String.stringLikeString)(dictMonad)(Data_Char_Unicode.isHexDigit))("hex digit");
  };
  var digit = function (dictMonad) {
      return Text_Parsing_Parser_Combinators.withErrorMessage(dictMonad)(Text_Parsing_Parser_String.satisfy(Text_Parsing_Parser_String.stringLikeString)(dictMonad)(Data_Char_Unicode.isDigit))("digit");
  };
  exports["digit"] = digit;
  exports["hexDigit"] = hexDigit;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Common"] = $PS["URI.Common"] || {};
  var exports = $PS["URI.Common"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Category = $PS["Control.Category"];
  var Control_Monad_Error_Class = $PS["Control.Monad.Error.Class"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Control_Monad_State_Class = $PS["Control.Monad.State.Class"];
  var Control_Monad_State_Trans = $PS["Control.Monad.State.Trans"];
  var Data_Array = $PS["Data.Array"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Global_Unsafe = $PS["Global.Unsafe"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var Text_Parsing_Parser_Token = $PS["Text.Parsing.Parser.Token"];
  var wrapParser = function (dictMonad) {
      return function (parseA) {
          return function (p) {
              return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Control_Monad_State_Trans.monadStateT(dictMonad)))(Control_Monad_State_Class.get(Control_Monad_Except_Trans.monadStateExceptT(Control_Monad_State_Trans.monadStateStateT(dictMonad))))(function (v) {
                  return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Control_Monad_State_Trans.monadStateT(dictMonad)))(Data_Newtype.un(Text_Parsing_Parser.newtypeParserT)(Text_Parsing_Parser.ParserT)(p))(function (a) {
                      var v1 = parseA(a);
                      if (v1 instanceof Data_Either.Left) {
                          return Control_Monad_Error_Class.throwError(Control_Monad_Except_Trans.monadThrowExceptT(Control_Monad_State_Trans.monadStateT(dictMonad)))(new Text_Parsing_Parser.ParseError(v1.value0, v.value1));
                      };
                      if (v1 instanceof Data_Either.Right) {
                          return Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Control_Monad_State_Trans.monadStateT(dictMonad)))(v1.value0);
                      };
                      throw new Error("Failed pattern match at URI.Common (line 56, column 3 - line 58, column 21): " + [ v1.constructor.name ]);
                  });
              });
          };
      };
  };
  var subDelims = Text_Parsing_Parser_String.oneOf(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)([ "!", "$", "&", "'", "(", ")", "*", "+", ";", "=", "," ]);
  var printEncoded = function (p) {
      return function (s) {
          var simpleChar = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_CodeUnits.singleton)(p);
          var encodedChar = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(function ($19) {
              return Global_Unsafe.unsafeEncodeURIComponent(Data_String_CodeUnits.singleton($19));
          })(Text_Parsing_Parser_String.anyChar(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity));
          var parse = Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_Common.joinWith(""))(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(simpleChar)(encodedChar))))(Text_Parsing_Parser_String.eof(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity));
          return Data_Either.either(Data_Function["const"](s))(Control_Category.identity(Control_Category.categoryFn))(Text_Parsing_Parser.runParser(s)(parse));
      };
  };
  var printEncoded$prime = function (p) {
      var $20 = Data_String_NonEmpty_Internal.unsafeFromString();
      var $21 = printEncoded(p);
      return function ($22) {
          return $20($21(Data_String_NonEmpty_Internal.toString($22)));
      };
  };
  var pctEncoded = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("%"))(function (d0) {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Token.hexDigit(Data_Identity.monadIdentity))(function (d1) {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Token.hexDigit(Data_Identity.monadIdentity))(function (d2) {
              return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(Data_Semigroup.append(Data_String_NonEmpty_Internal.semigroupNonEmptyString)(Data_String_NonEmpty_CodeUnits.singleton(d0))(Data_Semigroup.append(Data_String_NonEmpty_Internal.semigroupNonEmptyString)(Data_String_NonEmpty_CodeUnits.singleton(d1))(Data_String_NonEmpty_CodeUnits.singleton(d2))));
          });
      });
  });                                        
  var decodeURIComponent$prime = (function () {
      var $23 = Data_String_NonEmpty_Internal.unsafeFromString();
      return function ($24) {
          return $23(Global_Unsafe.unsafeDecodeURIComponent(Data_String_NonEmpty_Internal.toString($24)));
      };
  })();
  var alpha = Text_Parsing_Parser_String.satisfy(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(function (c) {
      return c >= "a" && c <= "z" || c >= "A" && c <= "Z";
  });
  var alphaNum = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(alpha)(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity));
  var unreserved = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(alphaNum)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("-")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(".")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("_")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("~"));
  exports["wrapParser"] = wrapParser;
  exports["alpha"] = alpha;
  exports["alphaNum"] = alphaNum;
  exports["unreserved"] = unreserved;
  exports["pctEncoded"] = pctEncoded;
  exports["subDelims"] = subDelims;
  exports["printEncoded"] = printEncoded;
  exports["printEncoded'"] = printEncoded$prime;
  exports["decodeURIComponent'"] = decodeURIComponent$prime;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Query"] = $PS["URI.Query"] || {};
  var exports = $PS["URI.Query"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Array = $PS["Data.Array"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];                
  var Query = function (x) {
      return x;
  };
  var unsafeFromString = Query;                       
  var queryChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(URI_Common.subDelims))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("@")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("/")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("?"));
  var print = function (v) {
      return "?" + v;
  };
  var parser = Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("?"))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
      var $8 = Data_String_NonEmpty_Internal.joinWith(Data_Foldable.foldableArray)("");
      return function ($9) {
          return Query($8($9));
      };
  })())(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_NonEmpty_CodeUnits.singleton)(queryChar))(URI_Common.pctEncoded))));
  exports["unsafeFromString"] = unsafeFromString;
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Extra.QueryPairs"] = $PS["URI.Extra.QueryPairs"] || {};
  var exports = $PS["URI.Extra.QueryPairs"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Array = $PS["Data.Array"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_String_Common = $PS["Data.String.Common"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];
  var URI_Query = $PS["URI.Query"];                
  var Value = function (x) {
      return x;
  };
  var QueryPairs = function (x) {
      return x;
  };
  var Key = function (x) {
      return x;
  };
  var unsafeValueToString = function (v) {
      return v;
  };                                
  var unsafeKeyToString = function (v) {
      return v;
  };                                                
  var print = function (printK) {
      return function (printV) {
          return function (v) {
              var printPart = function (v1) {
                  if (v1.value1 instanceof Data_Maybe.Nothing) {
                      return unsafeKeyToString(printK(v1.value0));
                  };
                  if (v1.value1 instanceof Data_Maybe.Just) {
                      return unsafeKeyToString(printK(v1.value0)) + ("=" + unsafeValueToString(printV(v1.value1.value0)));
                  };
                  throw new Error("Failed pattern match at URI.Extra.QueryPairs (line 101, column 17 - line 105, column 78): " + [ v1.constructor.name ]);
              };
              return URI_Query.unsafeFromString(Data_String_Common.joinWith("&")(Data_Array.fromFoldable(Data_Foldable.foldableArray)(Data_Functor.map(Data_Functor.functorArray)(printPart)(v))));
          };
      };
  };
  var keyPartChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(Text_Parsing_Parser_String.oneOf(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)([ "!", "$", "'", "(", ")", "*", "+", ",", ":", "@", "/", "?" ]));
  var valueFromString = (function () {
      var $37 = URI_Common.printEncoded(keyPartChar);
      return function ($38) {
          return Value($37($38));
      };
  })();
  var keyFromString = (function () {
      var $44 = URI_Common.printEncoded(keyPartChar);
      return function ($45) {
          return Key($44($45));
      };
  })();
  exports["QueryPairs"] = QueryPairs;
  exports["print"] = print;
  exports["keyFromString"] = keyFromString;
  exports["valueFromString"] = valueFromString;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.OAuth.Google"] = $PS["JohnCowie.OAuth.Google"] || {};
  var exports = $PS["JohnCowie.OAuth.Google"];
  var Affjax = $PS["Affjax"];
  var Affjax_RequestBody = $PS["Affjax.RequestBody"];
  var Affjax_ResponseFormat = $PS["Affjax.ResponseFormat"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Category = $PS["Control.Category"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Argonaut_Decode_Class = $PS["Data.Argonaut.Decode.Class"];
  var Data_Argonaut_Decode_Error = $PS["Data.Argonaut.Decode.Error"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_FormURLEncoded = $PS["Data.FormURLEncoded"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_HTTP_Method = $PS["Data.HTTP.Method"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Envisage_Internal = $PS["Envisage.Internal"];
  var Envisage_Logger = $PS["Envisage.Logger"];
  var Envisage_Record = $PS["Envisage.Record"];
  var Envisage_Var = $PS["Envisage.Var"];
  var JohnCowie_JWT = $PS["JohnCowie.JWT"];
  var JohnCowie_OAuth = $PS["JohnCowie.OAuth"];
  var Type_Equality = $PS["Type.Equality"];
  var URI_Extra_QueryPairs = $PS["URI.Extra.QueryPairs"];
  var URI_Query = $PS["URI.Query"];                
  var queryString = function (pairs) {
      return URI_Query.print(URI_Extra_QueryPairs.print(Control_Category.identity(Control_Category.categoryFn))(Control_Category.identity(Control_Category.categoryFn))(URI_Extra_QueryPairs.QueryPairs(Data_Functor.map(Data_Functor.functorArray)(function (v) {
          return new Data_Tuple.Tuple(URI_Extra_QueryPairs.keyFromString(v.value0), new Data_Maybe.Just(URI_Extra_QueryPairs.valueFromString(v.value1)));
      })(pairs))));
  };
  var redirect = function (config) {
      var query = queryString([ new Data_Tuple.Tuple("response_type", "code"), new Data_Tuple.Tuple("access_type", "online"), new Data_Tuple.Tuple("scope", "profile email"), new Data_Tuple.Tuple("prompt", "select_account consent"), new Data_Tuple.Tuple("client_id", config.clientId), new Data_Tuple.Tuple("redirect_uri", config.callbackUrl) ]);
      return config.oauthUrl + query;
  };
  var formData = function (tuples) {
      return Affjax_RequestBody.formURLEncoded(Data_FormURLEncoded.FormURLEncoded(Data_Functor.map(Data_Functor.functorArray)(Data_Functor.map(Data_Tuple.functorTuple)(Data_Maybe.Just.create))(tuples)));
  };
  var fetchOpenIdData = function (config) {
      return function (code) {
          var url = config.apiUrl + "/oauth2/v4/token";
          var body = formData([ new Data_Tuple.Tuple("code", Data_Newtype.unwrap(JohnCowie_OAuth.newtypeOAuthCode)(code)), new Data_Tuple.Tuple("client_id", config.clientId), new Data_Tuple.Tuple("client_secret", config.clientSecret), new Data_Tuple.Tuple("redirect_uri", config.callbackUrl), new Data_Tuple.Tuple("grant_type", "authorization_code") ]);
          var request = {
              responseFormat: Affjax_ResponseFormat.json,
              method: new Data_Either.Left(Data_HTTP_Method.POST.value),
              url: url,
              content: new Data_Maybe.Just(body),
              headers: Affjax.defaultRequest.headers,
              password: Affjax.defaultRequest.password,
              username: Affjax.defaultRequest.username,
              withCredentials: Affjax.defaultRequest.withCredentials
          };
          return Control_Monad_Except_Trans.runExceptT(Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(Effect_Aff.functorAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Affjax.printError))(Affjax.request(request))))(function (response) {
              return Control_Monad_Except_Trans.ExceptT(Control_Applicative.pure(Effect_Aff.applicativeAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Argonaut_Decode_Error.printJsonDecodeError)(Data_Argonaut_Decode_Class.decodeJson(Data_Argonaut_Decode_Class.decodeRecord(Data_Argonaut_Decode_Class.gDecodeJsonCons(JohnCowie_JWT.decodeJsonJWT)(Data_Argonaut_Decode_Class.gDecodeJsonCons(JohnCowie_JWT.decodeJsonJWT)(Data_Argonaut_Decode_Class.gDecodeJsonNil)(new Data_Symbol.IsSymbol(function () {
                  return "id_token";
              }))()())(new Data_Symbol.IsSymbol(function () {
                  return "access_token";
              }))()())())(response.body))));
          }));
      };
  };
  var handleCode = function (config) {
      return function (code) {
          return Control_Monad_Except_Trans.runExceptT(Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(fetchOpenIdData(config)(code)))(function (tokenData) {
              return Control_Monad_Except_Trans.ExceptT(Control_Applicative.pure(Effect_Aff.applicativeAff)(JohnCowie_JWT.extractPayload(Data_Argonaut_Decode_Class.decodeRecord(Data_Argonaut_Decode_Class.gDecodeJsonCons(Data_Argonaut_Decode_Class.decodeJsonString)(Data_Argonaut_Decode_Class.gDecodeJsonCons(Data_Argonaut_Decode_Class.decodeJsonString)(Data_Argonaut_Decode_Class.gDecodeJsonCons(Data_Argonaut_Decode_Class.decodeJsonString)(Data_Argonaut_Decode_Class.gDecodeJsonNil)(new Data_Symbol.IsSymbol(function () {
                  return "sub";
              }))()())(new Data_Symbol.IsSymbol(function () {
                  return "name";
              }))()())(new Data_Symbol.IsSymbol(function () {
                  return "email";
              }))()())())(tokenData.id_token)));
          }));
      };
  };
  var oauth = Envisage_Internal.mkComponent()()(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
      return "apiUrl";
  }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
      return "callbackUrl";
  }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
      return "clientId";
  }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
      return "clientSecret";
  }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
      return "oauthUrl";
  }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateNil(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Type_Equality.refl)))))))({
      oauthUrl: Envisage_Internal.showParsed(Data_Show.showString)(Envisage_Internal.defaultTo("https://accounts.google.com/o/oauth2/v2/auth")(Envisage_Var["var"](Envisage_Var.parseValueString)("GOOGLE_OAUTH_URL"))),
      apiUrl: Envisage_Internal.showParsed(Data_Show.showString)(Envisage_Internal.defaultTo("https://www.googleapis.com")(Envisage_Var["var"](Envisage_Var.parseValueString)("GOOGLE_API_URL"))),
      clientId: Envisage_Internal.showParsed(Data_Show.showString)(Envisage_Internal.describe("Client ID for google oauth account")(Envisage_Var["var"](Envisage_Var.parseValueString)("GOOGLE_CLIENT_ID"))),
      clientSecret: Envisage_Internal.describe("Client secret for google oauth integration")(Envisage_Var["var"](Envisage_Var.parseValueString)("GOOGLE_CLIENT_SECRET")),
      callbackUrl: Envisage_Internal.describe("Url for google to return to on oauth completion")(Envisage_Var["var"](Envisage_Var.parseValueString)("GOOGLE_CALLBACK_URL"))
  })(function (config) {
      return {
          redirect: redirect(config),
          handleCode: handleCode(config)
      };
  });
  exports["oauth"] = oauth;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.UserInfo"] = $PS["URI.UserInfo"] || {};
  var exports = $PS["URI.UserInfo"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Array_NonEmpty = $PS["Data.Array.NonEmpty"];
  var Data_Array_NonEmpty_Internal = $PS["Data.Array.NonEmpty.Internal"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];                
  var UserInfo = function (x) {
      return x;
  };
  var userInfoChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(URI_Common.subDelims))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":"));
  var unsafeToString = function (v) {
      return v;
  };
  var unsafeFromString = UserInfo;
  var parser = (function () {
      var parse = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_NonEmpty_CodeUnits.singleton)(userInfoChar))(URI_Common.pctEncoded);
      return Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
          var $7 = Data_String_NonEmpty_Internal.join1With(Data_Array_NonEmpty_Internal.foldable1NonEmptyArray)("");
          return function ($8) {
              return UserInfo($7($8));
          };
      })())(Data_Array_NonEmpty.some(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(parse));
  })();
  exports["unsafeFromString"] = unsafeFromString;
  exports["unsafeToString"] = unsafeToString;
  exports["parser"] = parser;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Authority"] = $PS["URI.Authority"] || {};
  var exports = $PS["URI.Authority"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Lens_Lens = $PS["Data.Lens.Lens"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];
  var URI_UserInfo = $PS["URI.UserInfo"];                
  var Authority = (function () {
      function Authority(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      Authority.create = function (value0) {
          return function (value1) {
              return new Authority(value0, value1);
          };
      };
      return Authority;
  })();
  var parser = function (opts) {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String.string(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("//"))(function () {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Combinators.optionMaybe(Data_Identity.monadIdentity)(Text_Parsing_Parser_Combinators["try"](Data_Identity.monadIdentity)(Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(URI_Common.wrapParser(Data_Identity.monadIdentity)(opts.parseUserInfo)(URI_UserInfo.parser))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("@")))))(function (ui) {
              return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(opts.parseHosts)(function (hosts) {
                  return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(new Authority(ui, hosts));
              });
          });
      });
  };
  var _userInfo = function (dictStrong) {
      return Data_Lens_Lens.lens(function (v) {
          return v.value0;
      })(function (v) {
          return function (ui) {
              return new Authority(ui, v.value1);
          };
      })(dictStrong);
  };
  var _hosts = function (dictStrong) {
      return Data_Lens_Lens.lens(function (v) {
          return v.value1;
      })(function (v) {
          return function (hs) {
              return new Authority(v.value0, hs);
          };
      })(dictStrong);
  };
  exports["parser"] = parser;
  exports["_userInfo"] = _userInfo;
  exports["_hosts"] = _hosts;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Path.Segment"] = $PS["URI.Path.Segment"] || {};
  var exports = $PS["URI.Path.Segment"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Array = $PS["Data.Array"];
  var Data_Array_NonEmpty = $PS["Data.Array.NonEmpty"];
  var Data_Array_NonEmpty_Internal = $PS["Data.Array.NonEmpty.Internal"];
  var Data_Foldable = $PS["Data.Foldable"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Global_Unsafe = $PS["Global.Unsafe"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];
  var PathSegmentNZ = function (x) {
      return x;
  };
  var PathSegment = function (x) {
      return x;
  }; 
  var segmentToString = function (v) {
      return Global_Unsafe.unsafeDecodeURIComponent(v);
  };
  var segmentNCChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(URI_Common.subDelims))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("@"));
  var segmentChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(segmentNCChar)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":"));                                                                                                                                                        
  var parseSegmentNZ = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
      var $28 = Data_String_NonEmpty_Internal.join1With(Data_Array_NonEmpty_Internal.foldable1NonEmptyArray)("");
      return function ($29) {
          return PathSegmentNZ($28($29));
      };
  })())(Data_Array_NonEmpty.some(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.pctEncoded)(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_NonEmpty_CodeUnits.singleton)(segmentChar))));
  var parseSegment = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
      var $30 = Data_String_NonEmpty_Internal.joinWith(Data_Foldable.foldableArray)("");
      return function ($31) {
          return PathSegment($30($31));
      };
  })())(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.pctEncoded)(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_NonEmpty_CodeUnits.singleton)(segmentChar))));
  exports["segmentToString"] = segmentToString;
  exports["parseSegment"] = parseSegment;
  exports["parseSegmentNZ"] = parseSegmentNZ;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Path"] = $PS["URI.Path"] || {};
  var exports = $PS["URI.Path"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Array = $PS["Data.Array"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Path_Segment = $PS["URI.Path.Segment"];                
  var Path = function (x) {
      return x;
  };
  var parser = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Path)(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("/"))(URI_Path_Segment.parseSegment)));
  exports["parser"] = parser;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Path.Absolute"] = $PS["URI.Path.Absolute"] || {};
  var exports = $PS["URI.Path.Absolute"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Array = $PS["Data.Array"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Path_Segment = $PS["URI.Path.Segment"];                
  var PathAbsolute = function (x) {
      return x;
  };
  var parse = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("/"))(function () {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Combinators.optionMaybe(Data_Identity.monadIdentity)(URI_Path_Segment.parseSegmentNZ))(function (v) {
          if (v instanceof Data_Maybe.Just) {
              return Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
                  var $27 = Data_Tuple.Tuple.create(v.value0);
                  return function ($28) {
                      return PathAbsolute(Data_Maybe.Just.create($27($28)));
                  };
              })())(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("/"))(URI_Path_Segment.parseSegment)));
          };
          if (v instanceof Data_Maybe.Nothing) {
              return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(Data_Maybe.Nothing.value);
          };
          throw new Error("Failed pattern match at URI.Path.Absolute (line 37, column 34 - line 41, column 34): " + [ v.constructor.name ]);
      });
  });
  exports["parse"] = parse;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Path.Rootless"] = $PS["URI.Path.Rootless"] || {};
  var exports = $PS["URI.Path.Rootless"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Array = $PS["Data.Array"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Tuple = $PS["Data.Tuple"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Path_Segment = $PS["URI.Path.Segment"];
  var parse = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(URI_Path_Segment.parseSegmentNZ)(function (head) {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("/"))(URI_Path_Segment.parseSegment)))(function (tail) {
          return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(new Data_Tuple.Tuple(head, tail));
      });
  });
  exports["parse"] = parse;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.HierarchicalPart"] = $PS["URI.HierarchicalPart"] || {};
  var exports = $PS["URI.HierarchicalPart"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Lens_Internal_Wander = $PS["Data.Lens.Internal.Wander"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var URI_Authority = $PS["URI.Authority"];
  var URI_Common = $PS["URI.Common"];
  var URI_Path = $PS["URI.Path"];
  var URI_Path_Absolute = $PS["URI.Path.Absolute"];
  var URI_Path_Rootless = $PS["URI.Path.Rootless"];                
  var HierarchicalPartAuth = (function () {
      function HierarchicalPartAuth(value0, value1) {
          this.value0 = value0;
          this.value1 = value1;
      };
      HierarchicalPartAuth.create = function (value0) {
          return function (value1) {
              return new HierarchicalPartAuth(value0, value1);
          };
      };
      return HierarchicalPartAuth;
  })();
  var HierarchicalPartNoAuth = (function () {
      function HierarchicalPartNoAuth(value0) {
          this.value0 = value0;
      };
      HierarchicalPartNoAuth.create = function (value0) {
          return new HierarchicalPartNoAuth(value0);
      };
      return HierarchicalPartNoAuth;
  })();
  var parser = function (opts) {
      var withAuth = Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(HierarchicalPartAuth.create)(URI_Authority.parser(opts)))(URI_Common.wrapParser(Data_Identity.monadIdentity)(opts.parsePath)(URI_Path.parser));
      var noAuthPath = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_Maybe.Just.create)(URI_Common.wrapParser(Data_Identity.monadIdentity)(function ($88) {
          return opts.parseHierPath(Data_Either.Left.create($88));
      })(URI_Path_Absolute.parse)))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_Maybe.Just.create)(URI_Common.wrapParser(Data_Identity.monadIdentity)(function ($89) {
          return opts.parseHierPath(Data_Either.Right.create($89));
      })(URI_Path_Rootless.parse))))(Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(Data_Maybe.Nothing.value));
      var withoutAuth = Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(HierarchicalPartNoAuth.create)(noAuthPath);
      return Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(withAuth)(withoutAuth);
  };
  var _path = function (dictWander) {
      return Data_Lens_Internal_Wander.wander(dictWander)(function (dictApplicative) {
          return function (f) {
              return function (v) {
                  if (v instanceof HierarchicalPartAuth) {
                      return Data_Functor.map((dictApplicative.Apply0()).Functor0())(HierarchicalPartAuth.create(v.value0))(f(v.value1));
                  };
                  return Control_Applicative.pure(dictApplicative)(v);
              };
          };
      });
  };
  var _authority = function (dictWander) {
      return Data_Lens_Internal_Wander.wander(dictWander)(function (dictApplicative) {
          return function (f) {
              return function (v) {
                  if (v instanceof HierarchicalPartAuth) {
                      return Data_Functor.map((dictApplicative.Apply0()).Functor0())(Data_Function.flip(HierarchicalPartAuth.create)(v.value1))(f(v.value0));
                  };
                  return Control_Applicative.pure(dictApplicative)(v);
              };
          };
      });
  };
  exports["parser"] = parser;
  exports["_authority"] = _authority;
  exports["_path"] = _path;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Scheme"] = $PS["URI.Scheme"] || {};
  var exports = $PS["URI.Scheme"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Array = $PS["Data.Array"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];                
  var Scheme = function (x) {
      return x;
  };
  var parseScheme = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(URI_Common.alpha)(function (init) {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Data_Array.many(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.alphaNum)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("+")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("-")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("."))))(function (rest) {
          return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(Data_String_NonEmpty_Internal.appendString(Data_String_NonEmpty_CodeUnits.singleton(init))(Data_String_CodeUnits.fromCharArray(rest)));
      });
  });
  var parser = Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Scheme)(parseScheme))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":"));
  exports["parser"] = parser;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.AbsoluteURI"] = $PS["URI.AbsoluteURI"] || {};
  var exports = $PS["URI.AbsoluteURI"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Lens_Lens = $PS["Data.Lens.Lens"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var URI_Common = $PS["URI.Common"];
  var URI_HierarchicalPart = $PS["URI.HierarchicalPart"];
  var URI_Query = $PS["URI.Query"];
  var URI_Scheme = $PS["URI.Scheme"];                
  var AbsoluteURI = (function () {
      function AbsoluteURI(value0, value1, value2) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
      };
      AbsoluteURI.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return new AbsoluteURI(value0, value1, value2);
              };
          };
      };
      return AbsoluteURI;
  })();
  var parser = function (opts) {
      return Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(AbsoluteURI.create)(URI_Scheme.parser))(URI_HierarchicalPart.parser(opts)))(Text_Parsing_Parser_Combinators.optionMaybe(Data_Identity.monadIdentity)(URI_Common.wrapParser(Data_Identity.monadIdentity)(opts.parseQuery)(URI_Query.parser))))(Text_Parsing_Parser_String.eof(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity));
  };
  var _hierPart = function (dictStrong) {
      return Data_Lens_Lens.lens(function (v) {
          return v.value1;
      })(function (v) {
          return function (h) {
              return new AbsoluteURI(v.value0, h, v.value2);
          };
      })(dictStrong);
  };
  exports["parser"] = parser;
  exports["_hierPart"] = _hierPart;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Extra.UserPassInfo"] = $PS["URI.Extra.UserPassInfo"] || {};
  var exports = $PS["URI.Extra.UserPassInfo"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Either = $PS["Data.Either"];
  var Data_Function = $PS["Data.Function"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var URI_Common = $PS["URI.Common"];
  var URI_UserInfo = $PS["URI.UserInfo"];                
  var UserPassInfo = function (x) {
      return x;
  };
  var userPassInfoChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(URI_Common.subDelims);
  var print = function (v) {
      if (v.password instanceof Data_Maybe.Nothing) {
          return URI_UserInfo.unsafeFromString(URI_Common["printEncoded'"](userPassInfoChar)(v.user));
      };
      if (v.password instanceof Data_Maybe.Just) {
          return URI_UserInfo.unsafeFromString(Data_Semigroup.append(Data_String_NonEmpty_Internal.semigroupNonEmptyString)(URI_Common["printEncoded'"](userPassInfoChar)(v.user))(Data_Semigroup.append(Data_String_NonEmpty_Internal.semigroupNonEmptyString)(Data_String_NonEmpty_CodeUnits.singleton(":"))(URI_Common["printEncoded'"](userPassInfoChar)(v.password.value0))));
      };
      throw new Error("Failed pattern match at URI.Extra.UserPassInfo (line 68, column 3 - line 75, column 44): " + [ v.password.constructor.name ]);
  };
  var parse = function (ui) {
      var s = URI_UserInfo.unsafeToString(ui);
      var v = Data_Functor.map(Data_Maybe.functorMaybe)(Data_Function.flip(Data_String_NonEmpty_CodeUnits.splitAt)(s))(Data_String_NonEmpty_CodeUnits.indexOf(":")(s));
      if (v instanceof Data_Maybe.Just && v.value0.before instanceof Data_Maybe.Nothing) {
          return new Data_Either.Left("Expected a username before a password segment");
      };
      if (v instanceof Data_Maybe.Just && (v.value0.before instanceof Data_Maybe.Just && v.value0.after instanceof Data_Maybe.Just)) {
          return Data_Either.Right.create({
              user: URI_Common["decodeURIComponent'"](v.value0.before.value0),
              password: Data_Functor.map(Data_Maybe.functorMaybe)(URI_Common["decodeURIComponent'"])(Data_String_NonEmpty_CodeUnits.drop(1)(v.value0.after.value0))
          });
      };
      return Data_Either.Right.create({
          user: URI_Common["decodeURIComponent'"](s),
          password: Data_Maybe.Nothing.value
      });
  };
  var newtypeUserPassInfo = new Data_Newtype.Newtype(function (n) {
      return n;
  }, UserPassInfo);
  exports["parse"] = parse;
  exports["print"] = print;
  exports["newtypeUserPassInfo"] = newtypeUserPassInfo;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Host.IPv4Address"] = $PS["URI.Host.IPv4Address"] || {};
  var exports = $PS["URI.Host.IPv4Address"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Int = $PS["Data.Int"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var Text_Parsing_Parser_Token = $PS["Text.Parsing.Parser.Token"];
  var URI_Common = $PS["URI.Common"];                
  var IPv4Address = (function () {
      function IPv4Address(value0, value1, value2, value3) {
          this.value0 = value0;
          this.value1 = value1;
          this.value2 = value2;
          this.value3 = value3;
      };
      IPv4Address.create = function (value0) {
          return function (value1) {
              return function (value2) {
                  return function (value3) {
                      return new IPv4Address(value0, value1, value2, value3);
                  };
              };
          };
      };
      return IPv4Address;
  })();
  var toInt = function (s) {
      var v = Data_Int.fromString(s);
      if (v instanceof Data_Maybe.Just && (v.value0 >= 0 && v.value0 <= 255)) {
          return new Data_Either.Right(v.value0);
      };
      return new Data_Either.Left("Invalid IPv4 address octet");
  }; 
  var print = function (v) {
      return Data_Show.show(Data_Show.showInt)(v.value0) + ("." + (Data_Show.show(Data_Show.showInt)(v.value1) + ("." + (Data_Show.show(Data_Show.showInt)(v.value2) + ("." + Data_Show.show(Data_Show.showInt)(v.value3))))));
  };
  var nzDigit = Text_Parsing_Parser_String.satisfy(Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(function (c) {
      return c >= "1" && c <= "9";
  });
  var octet = URI_Common.wrapParser(Data_Identity.monadIdentity)(toInt)(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Combinators["try"](Data_Identity.monadIdentity)(Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(function (x) {
      return function (y) {
          return function (z) {
              return Data_String_CodeUnits.fromCharArray([ x, y, z ]);
          };
      };
  })(nzDigit))(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity)))(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity))))(Text_Parsing_Parser_Combinators["try"](Data_Identity.monadIdentity)(Control_Apply.apply(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(function (x) {
      return function (y) {
          return Data_String_CodeUnits.fromCharArray([ x, y ]);
      };
  })(nzDigit))(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity)))))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_CodeUnits.singleton)(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity))));
  var parser = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(octet)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(".")))(function (o1) {
      return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(octet)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(".")))(function (o2) {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(octet)(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(".")))(function (o3) {
              return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(octet)(function (o4) {
                  return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(new IPv4Address(o1, o2, o3, o4));
              });
          });
      });
  });
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Host.IPv6Address"] = $PS["URI.Host.IPv6Address"] || {};
  var exports = $PS["URI.Host.IPv6Address"];
  var Control_Alt = $PS["Control.Alt"];
  var Control_Apply = $PS["Control.Apply"];
  var Data_Array = $PS["Data.Array"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var Text_Parsing_Parser_Token = $PS["Text.Parsing.Parser.Token"];                
  var IPv6Address = function (x) {
      return x;
  };
  var unsafeToString = function (v) {
      return "[" + (v + "]");
  }; 
  var parser = (function () {
      var ipv6Char = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Token.hexDigit(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":")))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("."));
      return Text_Parsing_Parser_Combinators.withErrorMessage(Data_Identity.monadIdentity)(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(IPv6Address)(Control_Apply.applyFirst(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("["))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_CodeUnits.fromCharArray)(Data_Array.some(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(ipv6Char))))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)("]"))))("IPv6 address");
  })();
  exports["unsafeToString"] = unsafeToString;
  exports["parser"] = parser;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Host.RegName"] = $PS["URI.Host.RegName"] || {};
  var exports = $PS["URI.Host.RegName"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Array_NonEmpty = $PS["Data.Array.NonEmpty"];
  var Data_Array_NonEmpty_Internal = $PS["Data.Array.NonEmpty.Internal"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_String_NonEmpty_CodeUnits = $PS["Data.String.NonEmpty.CodeUnits"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var URI_Common = $PS["URI.Common"];                
  var RegName = function (x) {
      return x;
  };
  var unsafeToString = function (v) {
      return v;
  };                             
  var toString = function (v) {
      return URI_Common["decodeURIComponent'"](v);
  };                                                                           
  var regNameChar = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.unreserved)(URI_Common.subDelims);
  var print = function ($6) {
      return Data_String_NonEmpty_Internal.toString(unsafeToString($6));
  };
  var parser = (function () {
      var p = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(URI_Common.pctEncoded)(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_NonEmpty_CodeUnits.singleton)(regNameChar));
      return Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))((function () {
          var $7 = Data_String_NonEmpty_Internal.join1With(Data_Array_NonEmpty_Internal.foldable1NonEmptyArray)("");
          return function ($8) {
              return RegName($7($8));
          };
      })())(Data_Array_NonEmpty.some(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(p));
  })();
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Host"] = $PS["URI.Host"] || {};
  var exports = $PS["URI.Host"];
  var Control_Alt = $PS["Control.Alt"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var URI_Host_IPv4Address = $PS["URI.Host.IPv4Address"];
  var URI_Host_IPv6Address = $PS["URI.Host.IPv6Address"];
  var URI_Host_RegName = $PS["URI.Host.RegName"];                
  var IPv6Address = (function () {
      function IPv6Address(value0) {
          this.value0 = value0;
      };
      IPv6Address.create = function (value0) {
          return new IPv6Address(value0);
      };
      return IPv6Address;
  })();
  var IPv4Address = (function () {
      function IPv4Address(value0) {
          this.value0 = value0;
      };
      IPv4Address.create = function (value0) {
          return new IPv4Address(value0);
      };
      return IPv4Address;
  })();
  var NameAddress = (function () {
      function NameAddress(value0) {
          this.value0 = value0;
      };
      NameAddress.create = function (value0) {
          return new NameAddress(value0);
      };
      return NameAddress;
  })();
  var print = function (v) {
      if (v instanceof IPv6Address) {
          return URI_Host_IPv6Address.unsafeToString(v.value0);
      };
      if (v instanceof IPv4Address) {
          return URI_Host_IPv4Address.print(v.value0);
      };
      if (v instanceof NameAddress) {
          return URI_Host_RegName.print(v.value0);
      };
      throw new Error("Failed pattern match at URI.Host (line 49, column 9 - line 52, column 40): " + [ v.constructor.name ]);
  };
  var parser = Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Control_Alt.alt(Text_Parsing_Parser.altParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(IPv6Address.create)(URI_Host_IPv6Address.parser))(Text_Parsing_Parser_Combinators["try"](Data_Identity.monadIdentity)(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(IPv4Address.create)(URI_Host_IPv4Address.parser))))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(NameAddress.create)(URI_Host_RegName.parser));
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.Port"] = $PS["URI.Port"] || {};
  var exports = $PS["URI.Port"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Apply = $PS["Control.Apply"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Array = $PS["Data.Array"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Int = $PS["Data.Int"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_CodeUnits = $PS["Data.String.CodeUnits"];
  var Global = $PS["Global"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_String = $PS["Text.Parsing.Parser.String"];
  var Text_Parsing_Parser_Token = $PS["Text.Parsing.Parser.Token"];
  var toInt = function (v) {
      return v;
  }; 
  var print = function (v) {
      return ":" + Data_Show.show(Data_Show.showInt)(v);
  };
  var parser = Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Data_Functor.map(Text_Parsing_Parser.functorParserT(Data_Identity.functorIdentity))(Data_String_CodeUnits.fromCharArray)(Control_Apply.applySecond(Text_Parsing_Parser.applyParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_String["char"](Text_Parsing_Parser_String.stringLikeString)(Data_Identity.monadIdentity)(":"))(Data_Array.some(Text_Parsing_Parser.alternativeParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser.lazyParserT)(Text_Parsing_Parser_Token.digit(Data_Identity.monadIdentity)))))(function (s) {
      var v = Data_Int.fromNumber(Global.readInt(10)(s));
      if (v instanceof Data_Maybe.Just) {
          return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))(v.value0);
      };
      return Text_Parsing_Parser.fail(Data_Identity.monadIdentity)("Expected a valid port number");
  });
  exports["toInt"] = toInt;
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["URI.HostPortPair"] = $PS["URI.HostPortPair"] || {};
  var exports = $PS["URI.HostPortPair"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Data_Identity = $PS["Data.Identity"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_These = $PS["Data.These"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var Text_Parsing_Parser_Combinators = $PS["Text.Parsing.Parser.Combinators"];
  var URI_Common = $PS["URI.Common"];
  var URI_Host = $PS["URI.Host"];
  var URI_Port = $PS["URI.Port"];                
  var print = function (printHost) {
      return function (printPort) {
          return function (v) {
              if (v instanceof Data_Maybe.Nothing) {
                  return "";
              };
              if (v instanceof Data_Maybe.Just && v.value0 instanceof Data_These.This) {
                  return URI_Host.print(printHost(v.value0.value0));
              };
              if (v instanceof Data_Maybe.Just && v.value0 instanceof Data_These.That) {
                  return URI_Port.print(printPort(v.value0.value0));
              };
              if (v instanceof Data_Maybe.Just && v.value0 instanceof Data_These.Both) {
                  return URI_Host.print(printHost(v.value0.value0)) + URI_Port.print(printPort(v.value0.value1));
              };
              throw new Error("Failed pattern match at URI.HostPortPair (line 58, column 29 - line 66, column 63): " + [ v.constructor.name ]);
          };
      };
  };
  var parser = function (parseHost) {
      return function (parsePort) {
          return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Combinators.optionMaybe(Data_Identity.monadIdentity)(URI_Common.wrapParser(Data_Identity.monadIdentity)(parseHost)(URI_Host.parser)))(function (mh) {
              return Control_Bind.bind(Text_Parsing_Parser.bindParserT(Data_Identity.monadIdentity))(Text_Parsing_Parser_Combinators.optionMaybe(Data_Identity.monadIdentity)(URI_Common.wrapParser(Data_Identity.monadIdentity)(parsePort)(URI_Port.parser)))(function (mp) {
                  return Control_Applicative.pure(Text_Parsing_Parser.applicativeParserT(Data_Identity.monadIdentity))((function () {
                      if (mh instanceof Data_Maybe.Just && mp instanceof Data_Maybe.Nothing) {
                          return new Data_Maybe.Just(new Data_These.This(mh.value0));
                      };
                      if (mh instanceof Data_Maybe.Nothing && mp instanceof Data_Maybe.Just) {
                          return new Data_Maybe.Just(new Data_These.That(mp.value0));
                      };
                      if (mh instanceof Data_Maybe.Just && mp instanceof Data_Maybe.Just) {
                          return new Data_Maybe.Just(new Data_These.Both(mh.value0, mp.value0));
                      };
                      if (mh instanceof Data_Maybe.Nothing && mp instanceof Data_Maybe.Nothing) {
                          return Data_Maybe.Nothing.value;
                      };
                      throw new Error("Failed pattern match at URI.HostPortPair (line 41, column 8 - line 45, column 31): " + [ mh.constructor.name, mp.constructor.name ]);
                  })());
              });
          });
      };
  };
  exports["parser"] = parser;
  exports["print"] = print;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.PostgreSQL.URI"] = $PS["JohnCowie.PostgreSQL.URI"] || {};
  var exports = $PS["JohnCowie.PostgreSQL.URI"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Category = $PS["Control.Category"];
  var Data_Array = $PS["Data.Array"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Lens_Fold = $PS["Data.Lens.Fold"];
  var Data_Lens_Internal_Forget = $PS["Data.Lens.Internal.Forget"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Maybe_Last = $PS["Data.Maybe.Last"];
  var Data_Newtype = $PS["Data.Newtype"];
  var Data_Show = $PS["Data.Show"];
  var Data_String_NonEmpty_Internal = $PS["Data.String.NonEmpty.Internal"];
  var Data_These = $PS["Data.These"];
  var Text_Parsing_Parser = $PS["Text.Parsing.Parser"];
  var URI_AbsoluteURI = $PS["URI.AbsoluteURI"];
  var URI_Authority = $PS["URI.Authority"];
  var URI_Extra_UserPassInfo = $PS["URI.Extra.UserPassInfo"];
  var URI_HierarchicalPart = $PS["URI.HierarchicalPart"];
  var URI_Host = $PS["URI.Host"];
  var URI_HostPortPair = $PS["URI.HostPortPair"];
  var URI_Path_Segment = $PS["URI.Path.Segment"];
  var URI_Port = $PS["URI.Port"];                
  var user = function (uri) {
      var userInfo = Control_Bind.join(Data_Maybe.bindMaybe)(Data_Lens_Fold.lastOf((function () {
          var $10 = URI_AbsoluteURI["_hierPart"](Data_Lens_Internal_Forget.strongForget);
          var $11 = URI_HierarchicalPart["_authority"](Data_Lens_Internal_Forget.wanderForget(Data_Maybe_Last.monoidLast));
          var $12 = URI_Authority["_userInfo"](Data_Lens_Internal_Forget.strongForget);
          return function ($13) {
              return $10($11($12($13)));
          };
      })())(uri));
      return Data_Functor.map(Data_Maybe.functorMaybe)(Data_Functor.map(Data_Functor.functorFn)(Data_Functor.map(Data_Functor.functorFn)(Data_String_NonEmpty_Internal.toString)(function (v) {
          return v.user;
      }))(Data_Newtype.unwrap(URI_Extra_UserPassInfo.newtypeUserPassInfo)))(userInfo);
  };
  var showError = function (dictShow) {
      return function (v) {
          if (v instanceof Data_Either.Left) {
              return Data_Either.Left.create(Data_Show.show(dictShow)(v.value0));
          };
          if (v instanceof Data_Either.Right) {
              return new Data_Either.Right(v.value0);
          };
          throw new Error("Failed pattern match at JohnCowie.PostgreSQL.URI (line 43, column 1 - line 43, column 73): " + [ v.constructor.name ]);
      };
  };
  var port = function (uri) {
      return Control_Bind.bind(Data_Maybe.bindMaybe)(Control_Bind.join(Data_Maybe.bindMaybe)(Data_Lens_Fold.lastOf((function () {
          var $14 = URI_AbsoluteURI["_hierPart"](Data_Lens_Internal_Forget.strongForget);
          var $15 = URI_HierarchicalPart["_authority"](Data_Lens_Internal_Forget.wanderForget(Data_Maybe_Last.monoidLast));
          var $16 = URI_Authority["_hosts"](Data_Lens_Internal_Forget.strongForget);
          return function ($17) {
              return $14($15($16($17)));
          };
      })())(uri)))(function (hostPortPair) {
          return Control_Bind.bind(Data_Maybe.bindMaybe)(Data_These.theseRight(hostPortPair))(function (port$prime) {
              return Control_Applicative.pure(Data_Maybe.applicativeMaybe)(URI_Port.toInt(port$prime));
          });
      });
  };
  var pathHead = function (v) {
      return Data_Functor.map(Data_Maybe.functorMaybe)(URI_Path_Segment.segmentToString)(Data_Array.head(v));
  };
  var password = function (uri) {
      var userInfoM = Control_Bind.join(Data_Maybe.bindMaybe)(Data_Lens_Fold.lastOf((function () {
          var $18 = URI_AbsoluteURI["_hierPart"](Data_Lens_Internal_Forget.strongForget);
          var $19 = URI_HierarchicalPart["_authority"](Data_Lens_Internal_Forget.wanderForget(Data_Maybe_Last.monoidLast));
          var $20 = URI_Authority["_userInfo"](Data_Lens_Internal_Forget.strongForget);
          return function ($21) {
              return $18($19($20($21)));
          };
      })())(uri));
      return Control_Bind.bind(Data_Maybe.bindMaybe)(userInfoM)(function (userInfo) {
          return Control_Bind.bind(Data_Maybe.bindMaybe)((Data_Newtype.unwrap(URI_Extra_UserPassInfo.newtypeUserPassInfo)(userInfo)).password)(function (password$prime) {
              return Control_Applicative.pure(Data_Maybe.applicativeMaybe)(Data_String_NonEmpty_Internal.toString(password$prime));
          });
      });
  };
  var options = {
      parseUserInfo: URI_Extra_UserPassInfo.parse,
      printUserInfo: URI_Extra_UserPassInfo.print,
      parseHosts: URI_HostPortPair.parser(Control_Applicative.pure(Data_Either.applicativeEither))(Control_Applicative.pure(Data_Either.applicativeEither)),
      printHosts: URI_HostPortPair.print(Control_Category.identity(Control_Category.categoryFn))(Control_Category.identity(Control_Category.categoryFn)),
      parsePath: Control_Applicative.pure(Data_Either.applicativeEither),
      printPath: Control_Category.identity(Control_Category.categoryFn),
      parseHierPath: Control_Applicative.pure(Data_Either.applicativeEither),
      printHierPath: Control_Category.identity(Control_Category.categoryFn),
      parseQuery: Control_Applicative.pure(Data_Either.applicativeEither),
      printQuery: Control_Category.identity(Control_Category.categoryFn)
  };
  var host = function (uri) {
      return Control_Bind.bind(Data_Maybe.bindMaybe)(Control_Bind.join(Data_Maybe.bindMaybe)(Data_Lens_Fold.lastOf((function () {
          var $22 = URI_AbsoluteURI["_hierPart"](Data_Lens_Internal_Forget.strongForget);
          var $23 = URI_HierarchicalPart["_authority"](Data_Lens_Internal_Forget.wanderForget(Data_Maybe_Last.monoidLast));
          var $24 = URI_Authority["_hosts"](Data_Lens_Internal_Forget.strongForget);
          return function ($25) {
              return $22($23($24($25)));
          };
      })())(uri)))(function (hostPortPair) {
          return Control_Bind.bind(Data_Maybe.bindMaybe)(Data_These.theseLeft(hostPortPair))(function (h) {
              return Control_Applicative.pure(Data_Maybe.applicativeMaybe)(URI_Host.print(h));
          });
      });
  };
  var database = function (uri) {
      var databaseM = Control_Bind.join(Data_Maybe.bindMaybe)(Data_Functor.map(Data_Maybe.functorMaybe)(pathHead)(Data_Lens_Fold.lastOf((function () {
          var $26 = URI_AbsoluteURI["_hierPart"](Data_Lens_Internal_Forget.strongForget);
          var $27 = URI_HierarchicalPart["_path"](Data_Lens_Internal_Forget.wanderForget(Data_Maybe_Last.monoidLast));
          return function ($28) {
              return $26($27($28));
          };
      })())(uri)));
      if (databaseM instanceof Data_Maybe.Just) {
          return new Data_Either.Right(databaseM.value0);
      };
      if (databaseM instanceof Data_Maybe.Nothing) {
          return new Data_Either.Left("URI doesn't have database specified");
      };
      throw new Error("Failed pattern match at JohnCowie.PostgreSQL.URI (line 64, column 16 - line 66, column 56): " + [ databaseM.constructor.name ]);
  };
  var uriToConfig = function (uri) {
      return Control_Bind.bind(Data_Either.bindEither)(database(uri))(function (database$prime) {
          return Control_Applicative.pure(Data_Either.applicativeEither)({
              database: database$prime,
              host: host(uri),
              idleTimeoutMillis: Data_Maybe.Nothing.value,
              max: Data_Maybe.Nothing.value,
              password: password(uri),
              user: user(uri),
              port: port(uri)
          });
      });
  };
  var fromURI = function (s) {
      return showError(Data_Show.showString)((function () {
          var p = URI_AbsoluteURI.parser(options);
          return Control_Bind.bind(Data_Either.bindEither)(showError(Text_Parsing_Parser.showParseError)(Text_Parsing_Parser.runParser(s)(p)))(function (uri) {
              return uriToConfig(uri);
          });
      })());
  };
  exports["fromURI"] = fromURI;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.PostgreSQL"] = $PS["JohnCowie.PostgreSQL"] || {};
  var exports = $PS["JohnCowie.PostgreSQL"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Database_PostgreSQL = $PS["Database.PostgreSQL"];
  var Database_PostgreSQL_PG = $PS["Database.PostgreSQL.PG"];
  var Effect = $PS["Effect"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];
  var Effect_Console = $PS["Effect.Console"];
  var Envisage_Internal = $PS["Envisage.Internal"];
  var Envisage_Logger = $PS["Envisage.Logger"];
  var Envisage_Record = $PS["Envisage.Record"];
  var Envisage_Var = $PS["Envisage.Var"];
  var JohnCowie_PostgreSQL_URI = $PS["JohnCowie.PostgreSQL.URI"];
  var Type_Equality = $PS["Type.Equality"];                
  var withTransaction = Database_PostgreSQL_PG.withTransaction(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.runExceptT);
  var withConnection = Database_PostgreSQL_PG.withConnection(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(Control_Monad_Except_Trans.runExceptT);
  var runQuery = function (pool) {
      return function (query) {
          return Control_Monad_Except_Trans.runExceptT(withConnection(pool)(function (conn) {
              return withTransaction(conn)(query(conn));
          }));
      };
  };
  var createConnectionPool = function (poolConfig) {
      return Database_PostgreSQL.newPool({
          database: poolConfig.database,
          host: poolConfig.host,
          idleTimeoutMillis: new Data_Maybe.Just(1000),
          max: poolConfig.max,
          password: poolConfig.password,
          port: poolConfig.port,
          user: poolConfig.user
      });
  };
  var connectionMsg = function (poolConfig) {
      var port = Data_Maybe.fromMaybe("")(Data_Functor.map(Data_Maybe.functorMaybe)(Data_Show.show(Data_Show.showInt))(poolConfig.port));
      var host = Data_Maybe.fromMaybe("")(poolConfig.host);
      var hostAndPort = host + (":" + port);
      return "Connected to database " + (poolConfig.database + (" at " + hostAndPort));
  };
  var getDB = function (dbUri) {
      var v = JohnCowie_PostgreSQL_URI.fromURI(dbUri);
      if (v instanceof Data_Either.Left) {
          return Control_Applicative.pure(Effect.applicativeEffect)(new Data_Either.Left(v.value0));
      };
      if (v instanceof Data_Either.Right) {
          return function __do() {
              var pool = createConnectionPool(v.value0)();
              Effect_Console.log(connectionMsg(v.value0))();
              return new Data_Either.Right(pool);
          };
      };
      throw new Error("Failed pattern match at JohnCowie.PostgreSQL (line 47, column 15 - line 52, column 22): " + [ v.constructor.name ]);
  };
  var dbComponent = function (uriDefault) {
      return Envisage_Internal.mkComponent()()(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
          return "dbUri";
      }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateNil(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Type_Equality.refl)))({
          dbUri: Envisage_Internal.defaultTo(uriDefault)(Envisage_Internal.describe("Postgres DB uri")(Envisage_Var["var"](Envisage_Var.parseValueString)("DATABASE_URI")))
      })(function (v) {
          return getDB(v.dbUri);
      });
  };
  exports["runQuery"] = runQuery;
  exports["dbComponent"] = dbComponent;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["JohnCowie.PostgreSQL.Migrations"] = $PS["JohnCowie.PostgreSQL.Migrations"] || {};
  var exports = $PS["JohnCowie.PostgreSQL.Migrations"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Array = $PS["Data.Array"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Show = $PS["Data.Show"];
  var Database_PostgreSQL = $PS["Database.PostgreSQL"];
  var Database_PostgreSQL_PG = $PS["Database.PostgreSQL.PG"];
  var Database_PostgreSQL_Row = $PS["Database.PostgreSQL.Row"];
  var Database_PostgreSQL_Value = $PS["Database.PostgreSQL.Value"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Aff_Class = $PS["Effect.Aff.Class"];
  var Effect_Class = $PS["Effect.Class"];
  var Effect_Console = $PS["Effect.Console"];
  var JohnCowie_PostgreSQL = $PS["JohnCowie.PostgreSQL"];                
  var updateVersionQuery = "\x0a  INSERT INTO  _migrations (id, description, type) VALUES ($1, $2, $3);\x0a";
  var updateIntVersion = function (pool) {
      return function (isUp) {
          return function (migration) {
              var migrationType = (function () {
                  if (isUp) {
                      return "UP";
                  };
                  return "DOWN";
              })();
              return Control_Monad_Except_Trans.runExceptT(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(Effect_Aff.functorAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Database_PostgreSQL.showPGError)))(JohnCowie_PostgreSQL.runQuery(pool)(function (conn) {
                  return Database_PostgreSQL_PG.execute(Database_PostgreSQL_Row.toSQLRowRow3(Database_PostgreSQL_Value.toSQLValueInt)(Database_PostgreSQL_Value.toSQLValueString)(Database_PostgreSQL_Value.toSQLValueString))(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(conn)(updateVersionQuery)(new Database_PostgreSQL_Row.Row3(migration.id, migration.description, migrationType));
              }))));
          };
      };
  };
  var retrieveVersionQuery = "\x0a  SELECT id FROM _migrations\x0a  ORDER BY created desc\x0a  LIMIT 1;\x0a";
  var executeMigration = function (dictShow) {
      return function (pool) {
          return function (id) {
              return function (query) {
                  return Control_Monad_Except_Trans.runExceptT(Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Effect_Class.liftEffect(Control_Monad_Except_Trans.monadEffectExceptT(Effect_Aff.monadEffectAff))(Effect_Console.log("Running migration: " + Data_Show.show(dictShow)(id))))(function () {
                      return Control_Monad_Except_Trans.ExceptT(Data_Functor.map(Effect_Aff.functorAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Database_PostgreSQL.showPGError)))(JohnCowie_PostgreSQL.runQuery(pool)(function (conn) {
                          return Database_PostgreSQL_PG.execute(Database_PostgreSQL_Row.toSQLRowRow0)(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(conn)(query)(Database_PostgreSQL_Row.Row0.value);
                      })));
                  }));
              };
          };
      };
  };
  var executor = function (dictShow) {
      return function (pool) {
          return {
              executeMigration: executeMigration(dictShow)(pool)
          };
      };
  };
  var createTableQuery = "\x0a  CREATE TABLE IF NOT EXISTS _migrations\x0a  ( id INTEGER PRIMARY KEY\x0a  , description VARCHAR\x0a  , type VARCHAR NOT NULL\x0a  , created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP\x0a  );\x0a";
  var currentIntVersion = function (pool) {
      return Control_Monad_Except_Trans.runExceptT(Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(Effect_Aff.functorAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Database_PostgreSQL.showPGError)))(JohnCowie_PostgreSQL.runQuery(pool)(function (conn) {
          return Database_PostgreSQL_PG.execute(Database_PostgreSQL_Row.toSQLRowRow0)(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(conn)(createTableQuery)(Database_PostgreSQL_Row.Row0.value);
      }))))(function () {
          return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Data_Functor.map(Effect_Aff.functorAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Data_Show.show(Database_PostgreSQL.showPGError)))(JohnCowie_PostgreSQL.runQuery(pool)(function (conn) {
              return Database_PostgreSQL_PG.query(Database_PostgreSQL_Row.toSQLRowRow0)(Database_PostgreSQL_Row.fromSQLRowRow1(Database_PostgreSQL_Value.fromSQLValueInt))(Control_Monad_Except_Trans.monadErrorExceptT(Effect_Aff.monadAff))(Effect_Aff_Class.monadAffExceptT(Effect_Aff_Class.monadAffAff))(conn)(retrieveVersionQuery)(Database_PostgreSQL_Row.Row0.value);
          }))))(function (rows) {
              return Control_Applicative.pure(Control_Monad_Except_Trans.applicativeExceptT(Effect_Aff.monadAff))(Data_Functor.map(Data_Maybe.functorMaybe)(function (v) {
                  return v.value0;
              })(Data_Array.head(rows)));
          });
      }));
  };
  var intVersionStore = function (pool) {
      return {
          currentVersion: currentIntVersion(pool),
          updateVersion: updateIntVersion(pool)
      };
  };
  exports["executor"] = executor;
  exports["intVersionStore"] = intVersionStore;
})(PS);
(function(exports) {
  "use strict";

  exports.process = process;
})(PS["Node.Process"] = PS["Node.Process"] || {});
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Node.Process"] = $PS["Node.Process"] || {};
  var exports = $PS["Node.Process"];
  var $foreign = $PS["Node.Process"];
  var Unsafe_Coerce = $PS["Unsafe.Coerce"];
  var mkEffect = Unsafe_Coerce.unsafeCoerce;
  var getEnv = mkEffect(function (v) {
      return $foreign.process.env;
  });
  exports["getEnv"] = getEnv;
})(PS);
(function($PS) {
  // Generated by purs version 0.13.8
  "use strict";
  $PS["Main"] = $PS["Main"] || {};
  var exports = $PS["Main"];
  var Control_Applicative = $PS["Control.Applicative"];
  var Control_Bind = $PS["Control.Bind"];
  var Control_Monad_Except_Trans = $PS["Control.Monad.Except.Trans"];
  var Data_Bifunctor = $PS["Data.Bifunctor"];
  var Data_Either = $PS["Data.Either"];
  var Data_Functor = $PS["Data.Functor"];
  var Data_Maybe = $PS["Data.Maybe"];
  var Data_Monoid = $PS["Data.Monoid"];
  var Data_Ord = $PS["Data.Ord"];
  var Data_Semigroup = $PS["Data.Semigroup"];
  var Data_Show = $PS["Data.Show"];
  var Data_Symbol = $PS["Data.Symbol"];
  var Data_Unit = $PS["Data.Unit"];
  var Effect = $PS["Effect"];
  var Effect_Aff = $PS["Effect.Aff"];
  var Effect_Class = $PS["Effect.Class"];
  var Effect_Console = $PS["Effect.Console"];
  var Envisage_Console = $PS["Envisage.Console"];
  var Envisage_Internal = $PS["Envisage.Internal"];
  var Envisage_Logger = $PS["Envisage.Logger"];
  var Envisage_Record = $PS["Envisage.Record"];
  var Envisage_Var = $PS["Envisage.Var"];
  var Fundoscopic_Handlers = $PS["Fundoscopic.Handlers"];
  var Fundoscopic_Migrations = $PS["Fundoscopic.Migrations"];
  var Fundoscopic_Routing = $PS["Fundoscopic.Routing"];
  var JohnCowie_Data_Lens = $PS["JohnCowie.Data.Lens"];
  var JohnCowie_HTTPure = $PS["JohnCowie.HTTPure"];
  var JohnCowie_Migrations = $PS["JohnCowie.Migrations"];
  var JohnCowie_OAuth_Google = $PS["JohnCowie.OAuth.Google"];
  var JohnCowie_PostgreSQL = $PS["JohnCowie.PostgreSQL"];
  var JohnCowie_PostgreSQL_Migrations = $PS["JohnCowie.PostgreSQL.Migrations"];
  var Node_Process = $PS["Node.Process"];
  var Type_Equality = $PS["Type.Equality"];                
  var Dev = (function () {
      function Dev() {

      };
      Dev.value = new Dev();
      return Dev;
  })();
  var showMode = new Data_Show.Show(function (v) {
      return "Dev";
  });
  var serverConfig = {
      port: Envisage_Internal.showParsed(Data_Show.showInt)(Envisage_Internal.defaultTo(9000)(Envisage_Internal.describe("Server port")(Envisage_Var["var"](Envisage_Var.parseValueInt)("PORT"))))
  };
  var migrator = function (pool) {
      return {
          executor: JohnCowie_PostgreSQL_Migrations.executor(Data_Show.showInt)(pool),
          migrationStore: Fundoscopic_Migrations.migrationStore(Effect_Aff.monadAff),
          versionStore: JohnCowie_PostgreSQL_Migrations.intVersionStore(pool),
          logger: (function () {
              var $14 = Effect_Class.liftEffect(Effect_Aff.monadEffectAff);
              return function ($15) {
                  return $14(Effect_Console.log($15));
              };
          })()
      };
  };
  var lookupHandler = function (deps) {
      return function (v) {
          if (v instanceof Data_Maybe.Nothing) {
              return Fundoscopic_Handlers.notFound(Effect_Aff.monadAff);
          };
          if (v instanceof Data_Maybe.Just) {
              if (v.value0 instanceof Fundoscopic_Routing.Home) {
                  return Fundoscopic_Handlers.home(Effect_Aff.monadAff);
              };
              if (v.value0 instanceof Fundoscopic_Routing.Login) {
                  return Fundoscopic_Handlers.login(Effect_Aff.monadAff)(deps.oauth);
              };
              throw new Error("Failed pattern match at Main (line 34, column 14 - line 36, column 34): " + [ v.value0.constructor.name ]);
          };
          throw new Error("Failed pattern match at Main (line 32, column 22 - line 36, column 34): " + [ v.constructor.name ]);
      };
  };
  var logError = function (eM) {
      return Control_Bind.bind(Effect_Aff.bindAff)(eM)(function (e) {
          if (e instanceof Data_Either.Left) {
              return Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(Effect_Console.error(e.value0));
          };
          return Control_Applicative.pure(Effect_Aff.applicativeAff)(Data_Unit.unit);
      });
  };
  var app = function (dictIsRequest) {
      return function (handlerLookup) {
          return function (req) {
              var path = JohnCowie_Data_Lens.view(JohnCowie_HTTPure["_path"](dictIsRequest))(req);
              var handlerId = Fundoscopic_Routing.handlerIdForPath(path);
              return handlerLookup(handlerId)(req);
          };
      };
  };
  var main = Effect_Aff.launchAff_(logError(Control_Monad_Except_Trans.runExceptT(Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(Data_Functor.map(Effect.functorEffect)(Data_Either.Right.create)(Node_Process.getEnv))))(function (env) {
      return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Control_Applicative.pure(Effect_Aff.applicativeAff)(Data_Bifunctor.lmap(Data_Either.bifunctorEither)(Envisage_Console.printErrorsForConsole)(Envisage_Internal.readEnv()()(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
          return "dbE";
      }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadComponent)(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
          return "oauth";
      }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadComponent)(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
          return "server";
      }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadRecord()()(Envisage_Record.recordUpdateCons(new Data_Symbol.IsSymbol(function () {
          return "port";
      }))()()()()()()(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Envisage_Logger.applyReaderLogger(Data_Semigroup.semigroupArray)(Data_Maybe.applyMaybe))(Envisage_Internal.hasFunctionReadVar(Envisage_Internal.readValueAll))(Envisage_Record.recordUpdateNil(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Type_Equality.refl))))(Envisage_Record.recordUpdateNil(Envisage_Logger.applicativeReaderLogger(Data_Monoid.monoidArray)(Data_Maybe.applicativeMaybe))(Type_Equality.refl)))))(env)({
          oauth: JohnCowie_OAuth_Google.oauth,
          server: serverConfig,
          dbE: JohnCowie_PostgreSQL.dbComponent("postgres://localhost:5432/fundoscopic")
      })))))(function (v) {
          return Control_Bind.bind(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(v.dbE)))(function (db) {
              var deps = {
                  oauth: v.oauth,
                  server: v.server,
                  db: db
              };
              return Control_Bind.discard(Control_Bind.discardUnit)(Control_Monad_Except_Trans.bindExceptT(Effect_Aff.monadAff))(Control_Monad_Except_Trans.ExceptT(JohnCowie_Migrations.migrate(Data_Show.showInt)(Data_Ord.ordInt)(Effect_Aff.monadAff)(migrator(db))))(function () {
                  return Data_Functor["void"](Control_Monad_Except_Trans.functorExceptT(Effect_Aff.functorAff))(Control_Monad_Except_Trans.ExceptT(Effect_Class.liftEffect(Effect_Aff.monadEffectAff)(Data_Functor.map(Effect.functorEffect)(Data_Either.Right.create)(JohnCowie_HTTPure["serve'"]({
                      port: deps.server.port,
                      backlog: Data_Maybe.Nothing.value,
                      hostname: "0.0.0.0"
                  })(app(JohnCowie_HTTPure.requestBasicRequest)(lookupHandler(deps)))(function __do() {
                      Effect_Console.log(" \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510")();
                      Effect_Console.log(" \u2502 Server now up on port " + (Data_Show.show(Data_Show.showInt)(9000) + "                 \u2502"))();
                      Effect_Console.log(" \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518")();
                      return Effect_Console.log("Mode: " + Data_Show.show(showMode)(Dev.value))();
                  })))));
              });
          });
      });
  }))));
  exports["Dev"] = Dev;
  exports["logError"] = logError;
  exports["lookupHandler"] = lookupHandler;
  exports["app"] = app;
  exports["serverConfig"] = serverConfig;
  exports["migrator"] = migrator;
  exports["main"] = main;
  exports["showMode"] = showMode;
})(PS);
PS["Main"].main();
},
"g2/go55S8FHWJYPYN107JwtMuT3QJrElQ4qJ5aAljEE=":
function (require, module, exports, __dirname, __filename) {
'use strict'

var extend = require('xtend/mutable')

module.exports = PostgresInterval

function PostgresInterval (raw) {
  if (!(this instanceof PostgresInterval)) {
    return new PostgresInterval(raw)
  }
  extend(this, parse(raw))
}
var properties = ['seconds', 'minutes', 'hours', 'days', 'months', 'years']
PostgresInterval.prototype.toPostgres = function () {
  var filtered = properties.filter(this.hasOwnProperty, this)

  // In addition to `properties`, we need to account for fractions of seconds.
  if (this.milliseconds && filtered.indexOf('seconds') < 0) {
    filtered.push('seconds')
  }

  if (filtered.length === 0) return '0'
  return filtered
    .map(function (property) {
      var value = this[property] || 0

      // Account for fractional part of seconds,
      // remove trailing zeroes.
      if (property === 'seconds' && this.milliseconds) {
        value = (value + this.milliseconds / 1000).toFixed(6).replace(/\.?0+$/, '')
      }

      return value + ' ' + property
    }, this)
    .join(' ')
}

var propertiesISOEquivalent = {
  years: 'Y',
  months: 'M',
  days: 'D',
  hours: 'H',
  minutes: 'M',
  seconds: 'S'
}
var dateProperties = ['years', 'months', 'days']
var timeProperties = ['hours', 'minutes', 'seconds']
// according to ISO 8601
PostgresInterval.prototype.toISOString = PostgresInterval.prototype.toISO = function () {
  var datePart = dateProperties
    .map(buildProperty, this)
    .join('')

  var timePart = timeProperties
    .map(buildProperty, this)
    .join('')

  return 'P' + datePart + 'T' + timePart

  function buildProperty (property) {
    var value = this[property] || 0

    // Account for fractional part of seconds,
    // remove trailing zeroes.
    if (property === 'seconds' && this.milliseconds) {
      value = (value + this.milliseconds / 1000).toFixed(6).replace(/0+$/, '')
    }

    return value + propertiesISOEquivalent[property]
  }
}

var NUMBER = '([+-]?\\d+)'
var YEAR = NUMBER + '\\s+years?'
var MONTH = NUMBER + '\\s+mons?'
var DAY = NUMBER + '\\s+days?'
var TIME = '([+-])?([\\d]*):(\\d\\d):(\\d\\d)\\.?(\\d{1,6})?'
var INTERVAL = new RegExp([YEAR, MONTH, DAY, TIME].map(function (regexString) {
  return '(' + regexString + ')?'
})
  .join('\\s*'))

// Positions of values in regex match
var positions = {
  years: 2,
  months: 4,
  days: 6,
  hours: 9,
  minutes: 10,
  seconds: 11,
  milliseconds: 12
}
// We can use negative time
var negatives = ['hours', 'minutes', 'seconds', 'milliseconds']

function parseMilliseconds (fraction) {
  // add omitted zeroes
  var microseconds = fraction + '000000'.slice(fraction.length)
  return parseInt(microseconds, 10) / 1000
}

function parse (interval) {
  if (!interval) return {}
  var matches = INTERVAL.exec(interval)
  var isNegative = matches[8] === '-'
  return Object.keys(positions)
    .reduce(function (parsed, property) {
      var position = positions[property]
      var value = matches[position]
      // no empty string
      if (!value) return parsed
      // milliseconds are actually microseconds (up to 6 digits)
      // with omitted trailing zeroes.
      value = property === 'milliseconds'
        ? parseMilliseconds(value)
        : parseInt(value, 10)
      // no zeros
      if (!value) return parsed
      if (isNegative && ~negatives.indexOf(property)) {
        value *= -1
      }
      parsed[property] = value
      return parsed
    }, {})
}

},
"gHulgO1CPlGGcsJ7QCKlastpO+BDSXM//B/m8yT7zuI=":
function (require, module, exports, __dirname, __filename) {
'use strict'

exports.parse = function (source, transform) {
  return new ArrayParser(source, transform).parse()
}

class ArrayParser {
  constructor (source, transform) {
    this.source = source
    this.transform = transform || identity
    this.position = 0
    this.entries = []
    this.recorded = []
    this.dimension = 0
  }

  isEof () {
    return this.position >= this.source.length
  }

  nextCharacter () {
    var character = this.source[this.position++]
    if (character === '\\') {
      return {
        value: this.source[this.position++],
        escaped: true
      }
    }
    return {
      value: character,
      escaped: false
    }
  }

  record (character) {
    this.recorded.push(character)
  }

  newEntry (includeEmpty) {
    var entry
    if (this.recorded.length > 0 || includeEmpty) {
      entry = this.recorded.join('')
      if (entry === 'NULL' && !includeEmpty) {
        entry = null
      }
      if (entry !== null) entry = this.transform(entry)
      this.entries.push(entry)
      this.recorded = []
    }
  }

  consumeDimensions () {
    if (this.source[0] === '[') {
      while (!this.isEof()) {
        var char = this.nextCharacter()
        if (char.value === '=') break
      }
    }
  }

  parse (nested) {
    var character, parser, quote
    this.consumeDimensions()
    while (!this.isEof()) {
      character = this.nextCharacter()
      if (character.value === '{' && !quote) {
        this.dimension++
        if (this.dimension > 1) {
          parser = new ArrayParser(this.source.substr(this.position - 1), this.transform)
          this.entries.push(parser.parse(true))
          this.position += parser.position - 2
        }
      } else if (character.value === '}' && !quote) {
        this.dimension--
        if (!this.dimension) {
          this.newEntry()
          if (nested) return this.entries
        }
      } else if (character.value === '"' && !character.escaped) {
        if (quote) this.newEntry(true)
        quote = !quote
      } else if (character.value === ',' && !quote) {
        this.newEntry()
      } else {
        this.record(character.value)
      }
    }
    if (this.dimension !== 0) {
      throw new Error('array dimension not balanced')
    }
    return this.entries
  }
}

function identity (value) {
  return value
}

},
"ivxPzUcGZhHgeKX6RYdXghUBzhJ5MemCxs/8au6lkz0=":
function (require, module, exports, __dirname, __filename) {
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const serializer_1 = require("./serializer");
exports.serialize = serializer_1.serialize;
const parser_1 = require("./parser");
function parse(stream, callback) {
    const parser = new parser_1.Parser();
    stream.on('data', (buffer) => parser.parse(buffer, callback));
    return new Promise((resolve) => stream.on('end', () => resolve()));
}
exports.parse = parse;
//# sourceMappingURL=index.js.map
},
"jjKg038gvW99W9v5nQQaonvkfLvlFyrBPr9zgKELO/Y=":
function (require, module, exports, __dirname, __filename) {
/**
 * Module dependencies.
 */

var fs = require('fs'),
  path = require('path'),
  fileURLToPath = require('file-uri-to-path'),
  join = path.join,
  dirname = path.dirname,
  exists =
    (fs.accessSync &&
      function(path) {
        try {
          fs.accessSync(path);
        } catch (e) {
          return false;
        }
        return true;
      }) ||
    fs.existsSync ||
    path.existsSync,
  defaults = {
    arrow: process.env.NODE_BINDINGS_ARROW || ' → ',
    compiled: process.env.NODE_BINDINGS_COMPILED_DIR || 'compiled',
    platform: process.platform,
    arch: process.arch,
    nodePreGyp:
      'node-v' +
      process.versions.modules +
      '-' +
      process.platform +
      '-' +
      process.arch,
    version: process.versions.node,
    bindings: 'bindings.node',
    try: [
      // node-gyp's linked version in the "build" dir
      ['module_root', 'build', 'bindings'],
      // node-waf and gyp_addon (a.k.a node-gyp)
      ['module_root', 'build', 'Debug', 'bindings'],
      ['module_root', 'build', 'Release', 'bindings'],
      // Debug files, for development (legacy behavior, remove for node v0.9)
      ['module_root', 'out', 'Debug', 'bindings'],
      ['module_root', 'Debug', 'bindings'],
      // Release files, but manually compiled (legacy behavior, remove for node v0.9)
      ['module_root', 'out', 'Release', 'bindings'],
      ['module_root', 'Release', 'bindings'],
      // Legacy from node-waf, node <= 0.4.x
      ['module_root', 'build', 'default', 'bindings'],
      // Production "Release" buildtype binary (meh...)
      ['module_root', 'compiled', 'version', 'platform', 'arch', 'bindings'],
      // node-qbs builds
      ['module_root', 'addon-build', 'release', 'install-root', 'bindings'],
      ['module_root', 'addon-build', 'debug', 'install-root', 'bindings'],
      ['module_root', 'addon-build', 'default', 'install-root', 'bindings'],
      // node-pre-gyp path ./lib/binding/{node_abi}-{platform}-{arch}
      ['module_root', 'lib', 'binding', 'nodePreGyp', 'bindings']
    ]
  };

/**
 * The main `bindings()` function loads the compiled bindings for a given module.
 * It uses V8's Error API to determine the parent filename that this function is
 * being invoked from, which is then used to find the root directory.
 */

function bindings(opts) {
  // Argument surgery
  if (typeof opts == 'string') {
    opts = { bindings: opts };
  } else if (!opts) {
    opts = {};
  }

  // maps `defaults` onto `opts` object
  Object.keys(defaults).map(function(i) {
    if (!(i in opts)) opts[i] = defaults[i];
  });

  // Get the module root
  if (!opts.module_root) {
    opts.module_root = exports.getRoot(exports.getFileName());
  }

  // Ensure the given bindings name ends with .node
  if (path.extname(opts.bindings) != '.node') {
    opts.bindings += '.node';
  }

  // https://github.com/webpack/webpack/issues/4175#issuecomment-342931035
  var requireFunc =
    typeof __webpack_require__ === 'function'
      ? __non_webpack_require__
      : require;

  var tries = [],
    i = 0,
    l = opts.try.length,
    n,
    b,
    err;

  for (; i < l; i++) {
    n = join.apply(
      null,
      opts.try[i].map(function(p) {
        return opts[p] || p;
      })
    );
    tries.push(n);
    try {
      b = opts.path ? requireFunc.resolve(n) : requireFunc(n);
      if (!opts.path) {
        b.path = n;
      }
      return b;
    } catch (e) {
      if (e.code !== 'MODULE_NOT_FOUND' &&
          e.code !== 'QUALIFIED_PATH_RESOLUTION_FAILED' &&
          !/not find/i.test(e.message)) {
        throw e;
      }
    }
  }

  err = new Error(
    'Could not locate the bindings file. Tried:\n' +
      tries
        .map(function(a) {
          return opts.arrow + a;
        })
        .join('\n')
  );
  err.tries = tries;
  throw err;
}
module.exports = exports = bindings;

/**
 * Gets the filename of the JavaScript file that invokes this function.
 * Used to help find the root directory of a module.
 * Optionally accepts an filename argument to skip when searching for the invoking filename
 */

exports.getFileName = function getFileName(calling_file) {
  var origPST = Error.prepareStackTrace,
    origSTL = Error.stackTraceLimit,
    dummy = {},
    fileName;

  Error.stackTraceLimit = 10;

  Error.prepareStackTrace = function(e, st) {
    for (var i = 0, l = st.length; i < l; i++) {
      fileName = st[i].getFileName();
      if (fileName !== __filename) {
        if (calling_file) {
          if (fileName !== calling_file) {
            return;
          }
        } else {
          return;
        }
      }
    }
  };

  // run the 'prepareStackTrace' function above
  Error.captureStackTrace(dummy);
  dummy.stack;

  // cleanup
  Error.prepareStackTrace = origPST;
  Error.stackTraceLimit = origSTL;

  // handle filename that starts with "file://"
  var fileSchema = 'file://';
  if (fileName.indexOf(fileSchema) === 0) {
    fileName = fileURLToPath(fileName);
  }

  return fileName;
};

/**
 * Gets the root directory of a module, given an arbitrary filename
 * somewhere in the module tree. The "root directory" is the directory
 * containing the `package.json` file.
 *
 *   In:  /home/nate/node-native-module/lib/index.js
 *   Out: /home/nate/node-native-module
 */

exports.getRoot = function getRoot(file) {
  var dir = dirname(file),
    prev;
  while (true) {
    if (dir === '.') {
      // Avoids an infinite loop in rare cases, like the REPL
      dir = process.cwd();
    }
    if (
      exists(join(dir, 'package.json')) ||
      exists(join(dir, 'node_modules'))
    ) {
      // Found the 'package.json' file or 'node_modules' dir; we're done
      return dir;
    }
    if (prev === dir) {
      // Got to the top
      throw new Error(
        'Could not find module root given file: "' +
          file +
          '". Do you have a `package.json` file? '
      );
    }
    // Try the parent dir next
    prev = dir;
    dir = join(dir, '..');
  }
};

},
"mfthy3im14t6X8C5rCZK1YJyr0i+S8UL/blIsTQuMpI=":
function (require, module, exports, __dirname, __filename) {
'use strict'
module.exports = require('./client')

},
"o+w5yxsBUAN7YU9TURngynJtL7CrEHeDiIo22OKkZrM=":
function (require, module, exports, __dirname, __filename) {
'use strict'

var DATE_TIME = /(\d{1,})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(\.\d{1,})?.*?( BC)?$/
var DATE = /^(\d{1,})-(\d{2})-(\d{2})( BC)?$/
var TIME_ZONE = /([Z+-])(\d{2})?:?(\d{2})?:?(\d{2})?/
var INFINITY = /^-?infinity$/

module.exports = function parseDate (isoDate) {
  if (INFINITY.test(isoDate)) {
    // Capitalize to Infinity before passing to Number
    return Number(isoDate.replace('i', 'I'))
  }
  var matches = DATE_TIME.exec(isoDate)

  if (!matches) {
    // Force YYYY-MM-DD dates to be parsed as local time
    return getDate(isoDate) || null
  }

  var isBC = !!matches[8]
  var year = parseInt(matches[1], 10)
  if (isBC) {
    year = bcYearToNegativeYear(year)
  }

  var month = parseInt(matches[2], 10) - 1
  var day = matches[3]
  var hour = parseInt(matches[4], 10)
  var minute = parseInt(matches[5], 10)
  var second = parseInt(matches[6], 10)

  var ms = matches[7]
  ms = ms ? 1000 * parseFloat(ms) : 0

  var date
  var offset = timeZoneOffset(isoDate)
  if (offset != null) {
    date = new Date(Date.UTC(year, month, day, hour, minute, second, ms))

    // Account for years from 0 to 99 being interpreted as 1900-1999
    // by Date.UTC / the multi-argument form of the Date constructor
    if (is0To99(year)) {
      date.setUTCFullYear(year)
    }

    date.setTime(date.getTime() - offset)
  } else {
    date = new Date(year, month, day, hour, minute, second, ms)

    if (is0To99(year)) {
      date.setFullYear(year)
    }
  }

  return date
}

function getDate (isoDate) {
  var matches = DATE.exec(isoDate)
  if (!matches) {
    return
  }

  var year = parseInt(matches[1], 10)
  var isBC = !!matches[4]
  if (isBC) {
    year = bcYearToNegativeYear(year)
  }

  var month = parseInt(matches[2], 10) - 1
  var day = matches[3]
  // YYYY-MM-DD will be parsed as local time
  var date = new Date(year, month, day)

  if (is0To99(year)) {
    date.setFullYear(year)
  }

  return date
}

// match timezones:
// Z (UTC)
// -05
// +06:30
function timeZoneOffset (isoDate) {
  var zone = TIME_ZONE.exec(isoDate.split(' ')[1])
  if (!zone) return
  var type = zone[1]

  if (type === 'Z') {
    return 0
  }
  var sign = type === '-' ? -1 : 1
  var offset = parseInt(zone[2], 10) * 3600 +
    parseInt(zone[3] || 0, 10) * 60 +
    parseInt(zone[4] || 0, 10)

  return offset * sign * 1000
}

function bcYearToNegativeYear (year) {
  // Account for numerical difference between representations of BC years
  // See: https://github.com/bendrucker/postgres-date/issues/5
  return -(year - 1)
}

function is0To99 (num) {
  return num >= 0 && num < 100
}

},
"pO4OwnzZqJGhpwHeyji45JH7ZUzNHU/rCUXCdx0xRUA=":
function (require, module, exports, __dirname, __filename) {
module.exports = {
  "_from": "pg-native",
  "_id": "pg-native@3.0.0",
  "_inBundle": false,
  "_integrity": "sha512-qZZyywXJ8O4lbiIN7mn6vXIow1fd3QZFqzRe+uET/SZIXvCa3HBooXQA4ZU8EQX8Ae6SmaYtDGLp5DwU+8vrfg==",
  "_location": "/pg-native",
  "_phantomChildren": {
    "core-util-is": "1.0.2",
    "inherits": "2.0.4",
    "pg-int8": "1.0.1",
    "postgres-bytea": "1.0.0",
    "postgres-date": "1.0.6",
    "postgres-interval": "1.2.0"
  },
  "_requested": {
    "type": "tag",
    "registry": true,
    "raw": "pg-native",
    "name": "pg-native",
    "escapedName": "pg-native",
    "rawSpec": "",
    "saveSpec": null,
    "fetchSpec": "latest"
  },
  "_requiredBy": [
    "#DEV:/",
    "#USER"
  ],
  "_resolved": "https://registry.npmjs.org/pg-native/-/pg-native-3.0.0.tgz",
  "_shasum": "20c64e651e20b28f5c060b3823522d1c8c4429c3",
  "_spec": "pg-native",
  "_where": "/Users/johncowie/Projects/purescript/fundoscopic",
  "author": {
    "name": "Brian M. Carlson"
  },
  "bugs": {
    "url": "https://github.com/brianc/node-pg-native/issues"
  },
  "bundleDependencies": false,
  "dependencies": {
    "libpq": "^1.7.0",
    "pg-types": "^1.12.1",
    "readable-stream": "1.0.31"
  },
  "deprecated": false,
  "description": "A slightly nicer interface to Postgres over node-libpq",
  "devDependencies": {
    "async": "^0.9.0",
    "concat-stream": "^1.4.6",
    "eslint": "4.2.0",
    "eslint-config-standard": "10.2.1",
    "eslint-plugin-import": "2.7.0",
    "eslint-plugin-node": "5.1.0",
    "eslint-plugin-promise": "3.5.0",
    "eslint-plugin-standard": "3.0.1",
    "generic-pool": "^2.1.1",
    "lodash": "^2.4.1",
    "mocha": "3.4.2",
    "okay": "^0.3.0",
    "pg": "*",
    "semver": "^4.1.0"
  },
  "homepage": "https://github.com/brianc/node-pg-native",
  "keywords": [
    "postgres",
    "pg",
    "libpq"
  ],
  "license": "MIT",
  "main": "index.js",
  "name": "pg-native",
  "repository": {
    "type": "git",
    "url": "git://github.com/brianc/node-pg-native.git"
  },
  "scripts": {
    "test": "mocha && eslint ."
  },
  "version": "3.0.0"
}

},
"pxUwCL/NaJJErBzfOJVnSSyfoCILL5oPs+x0yEQzx0k=":
function (require, module, exports, __dirname, __filename) {
var PQ = module.exports = require('bindings')('addon.node').PQ;

//print out the include dir
//if you want to include this in a binding.gyp file
if(!module.parent) {
  var path = require('path');
  console.log(path.normalize(__dirname + '/src'));
}

var EventEmitter = require('events').EventEmitter;
var assert = require('assert');

for(var key in EventEmitter.prototype) {
  PQ.prototype[key] = EventEmitter.prototype[key];
}

//SYNC connects to the server
//throws an exception in the event of a connection error
PQ.prototype.connectSync = function(paramString) {
  this.connected = true;
  if(!paramString) {
    paramString = '';
  }
  var connected = this.$connectSync(paramString);
  if(!connected) {
    var err = new Error(this.errorMessage());
    this.finish();
    throw err;
  }
};

//connects async using a background thread
//calls the callback with an error if there was one
PQ.prototype.connect = function(paramString, cb) {
  this.connected = true;
  if(typeof paramString == 'function') {
    cb = paramString;
    paramString = '';
  }
  if(!paramString) {
    paramString = '';
  }
  assert(cb, 'Must provide a connection callback');
  if(process.domain) {
    cb = process.domain.bind(cb);
  }
  this.$connect(paramString, cb);
};

PQ.prototype.errorMessage = function() {
  return this.$getLastErrorMessage();
};

//returns an int for the fd of the socket
PQ.prototype.socket = function() {
  return this.$socket();
};

// return server version number e.g. 90300
PQ.prototype.serverVersion = function () {
  return this.$serverVersion();
};

//finishes the connection & closes it
PQ.prototype.finish = function() {
  this.connected = false;
  this.$finish();
};

////SYNC executes a plain text query
//immediately stores the results within the PQ object for consumption with
//ntuples, getvalue, etc...
//returns false if there was an error
//consume additional error details via PQ#errorMessage & friends
PQ.prototype.exec = function(commandText) {
  if(!commandText) {
    commandText = '';
  }
  this.$exec(commandText);
};

//SYNC executes a query with parameters
//immediately stores the results within the PQ object for consumption with
//ntuples, getvalue, etc...
//returns false if there was an error
//consume additional error details via PQ#errorMessage & friends
PQ.prototype.execParams = function(commandText, parameters) {
  if(!commandText) {
    commandText = '';
  }
  if(!parameters) {
    parameters = [];
  }
  this.$execParams(commandText, parameters);
};

//SYNC prepares a named query and stores the result
//immediately stores the results within the PQ object for consumption with
//ntuples, getvalue, etc...
//returns false if there was an error
//consume additional error details via PQ#errorMessage & friends
PQ.prototype.prepare = function(statementName, commandText, nParams) {
  assert.equal(arguments.length, 3, 'Must supply 3 arguments');
  if(!statementName) {
    statementName = '';
  }
  if(!commandText) {
    commandText = '';
  }
  nParams = Number(nParams) || 0;
  this.$prepare(statementName, commandText, nParams);
};

//SYNC executes a named, prepared query and stores the result
//immediately stores the results within the PQ object for consumption with
//ntuples, getvalue, etc...
//returns false if there was an error
//consume additional error details via PQ#errorMessage & friends
PQ.prototype.execPrepared = function(statementName, parameters) {
  if(!statementName) {
    statementName = '';
  }
  if(!parameters) {
    parameters = [];
  }
  this.$execPrepared(statementName, parameters);
};

//send a command to begin executing a query in async mode
//returns true if sent, or false if there was a send failure
PQ.prototype.sendQuery = function(commandText) {
  if(!commandText) {
    commandText = '';
  }
  return this.$sendQuery(commandText);
};

//send a command to begin executing a query with parameters in async mode
//returns true if sent, or false if there was a send failure
PQ.prototype.sendQueryParams = function(commandText, parameters) {
  if(!commandText) {
    commandText = '';
  }
  if(!parameters) {
    parameters = [];
  }
  return this.$sendQueryParams(commandText, parameters);
};

//send a command to prepare a named query in async mode
//returns true if sent, or false if there was a send failure
PQ.prototype.sendPrepare = function(statementName, commandText, nParams) {
  assert.equal(arguments.length, 3, 'Must supply 3 arguments');
  if(!statementName) {
    statementName = '';
  }
  if(!commandText) {
    commandText = '';
  }
  nParams = Number(nParams) || 0;
  return this.$sendPrepare(statementName, commandText, nParams);
};

//send a command to execute a named query in async mode
//returns true if sent, or false if there was a send failure
PQ.prototype.sendQueryPrepared = function(statementName, parameters) {
  if(!statementName) {
    statementName = '';
  }
  if(!parameters) {
    parameters = [];
  }
  return this.$sendQueryPrepared(statementName, parameters);
};

//'pops' a result out of the buffered
//response data read during async command execution
//and stores it on the c/c++ object so you can consume
//the data from it.  returns true if there was a pending result
//or false if there was no pending result. if there was no pending result
//the last found result is not overwritten so you can call getResult as many
//times as you want, and you'll always have the last available result for consumption
PQ.prototype.getResult = function() {
  return this.$getResult();
};

//returns a text of the enum associated with the result
//usually just PGRES_COMMAND_OK or PGRES_FATAL_ERROR
PQ.prototype.resultStatus = function() {
  return this.$resultStatus();
};

PQ.prototype.resultErrorMessage = function() {
  return this.$resultErrorMessage();
};

PQ.prototype.resultErrorFields = function() {
  return this.$resultErrorFields();
};

//free the memory associated with a result
//this is somewhat handled for you within the c/c++ code
//by never allowing the code to 'leak' a result. still,
//if you absolutely want to free it yourself, you can use this.
PQ.prototype.clear = function() {
  this.$clear();
};

//returns the number of tuples (rows) in the result set
PQ.prototype.ntuples = function() {
  return this.$ntuples();
};

//returns the number of fields (columns) in the result set
PQ.prototype.nfields = function() {
  return this.$nfields();
};

//returns the name of the field (column) at the given offset
PQ.prototype.fname = function(offset) {
  return this.$fname(offset);
};

//returns the Oid of the type for the given field
PQ.prototype.ftype = function(offset) {
  return this.$ftype(offset);
};

//returns a text value at the given row/col
//if the value is null this still returns empty string
//so you need to use PQ#getisnull to determine
PQ.prototype.getvalue = function(row, col) {
  return this.$getvalue(row, col);
};

//returns true/false if the value is null
PQ.prototype.getisnull = function(row, col) {
  return this.$getisnull(row, col);
};

//returns the status of the command
PQ.prototype.cmdStatus = function() {
  return this.$cmdStatus();
};

//returns the tuples in the command
PQ.prototype.cmdTuples = function() {
  return this.$cmdTuples();
};

//starts the 'read ready' libuv socket listener.
//Once the socket becomes readable, the PQ instance starts
//emitting 'readable' events.  Similar to how node's readable-stream
//works except to clear the SELECT() notification you need to call
//PQ#consumeInput instead of letting node pull the data off the socket
//http://www.postgresql.org/docs/9.1/static/libpq-async.html
PQ.prototype.startReader = function() {
  assert(this.connected, 'Must be connected to start reader');
  this.$startRead();
};

//suspends the libuv socket 'read ready' listener
PQ.prototype.stopReader = function() {
  this.$stopRead();
};

PQ.prototype.writable = function(cb) {
  assert(this.connected, 'Must be connected to start writer');
  this.$startWrite();
  return this.once('writable', cb);
};

//returns boolean - false indicates an error condition
//e.g. a failure to consume input
PQ.prototype.consumeInput = function() {
  return this.$consumeInput();
};

//returns true if PQ#getResult would cause
//the process to block waiting on results
//false indicates PQ#getResult can be called
//with an assurance of not blocking
PQ.prototype.isBusy = function() {
  return this.$isBusy();
};

//toggles the socket blocking on outgoing writes
PQ.prototype.setNonBlocking = function(truthy) {
  return this.$setNonBlocking(truthy ? 1 : 0);
};

//returns true if the connection is non-blocking on writes, otherwise false
//note: connection is always non-blocking on reads if using the send* methods
PQ.prototype.isNonBlocking = function() {
  return this.$isNonBlocking();
};

//returns 1 if socket is not write-ready
//returns 0 if all data flushed to socket
//returns -1 if there is an error
PQ.prototype.flush = function() {
  return this.$flush();
};

//escapes a literal and returns the escaped string
//I'm not 100% sure this doesn't do any I/O...need to check that
PQ.prototype.escapeLiteral = function(input) {
  if(!input) return input;
  return this.$escapeLiteral(input);
};

PQ.prototype.escapeIdentifier = function(input) {
  if(!input) return input;
  return this.$escapeIdentifier(input);
};

//Checks for any notifications which may have arrivied
//and returns them as a javascript object: {relname: 'string', extra: 'string', be_pid: int}
//if there are no pending notifications this returns undefined
PQ.prototype.notifies = function() {
  return this.$notifies();
};

//Sends a buffer of binary data to the server
//returns 1 if the command was sent successfully
//returns 0 if the command would block (use PQ#writable here if so)
//returns -1 if there was an error
PQ.prototype.putCopyData = function(buffer) {
  assert(buffer instanceof Buffer);
  return this.$putCopyData(buffer);
};

//Sends a command to 'finish' the copy
//if an error message is passed, it will be sent to the
//backend and signal a request to cancel the copy in
//returns 1 if sent succesfully
//returns 0 if the command would block
//returns -1 if there was an error
PQ.prototype.putCopyEnd = function(errorMessage) {
  if(errorMessage) {
    return this.$putCopyEnd(errorMessage);
  }
  return this.$putCopyEnd();
};

//Gets a buffer of data from a copy out command
//if async is passed as true it will not block waiting
//for the result, otherwise this will BLOCK for a result.
//returns a buffer if successful
//returns 0 if copy is still in process (async only)
//returns -1 if the copy is done
//returns -2 if there was an error
PQ.prototype.getCopyData = function(async) {
  return this.$getCopyData(!!async);
};

PQ.prototype.cancel = function() {
  return this.$cancel();
};

},
"qffaFyIlqe0KpTmg1FdGSsiUKiEXeLQA9jQMuv99JF8=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

const crypto = require('crypto')

const defaults = require('./defaults')

function escapeElement(elementRepresentation) {
  var escaped = elementRepresentation.replace(/\\/g, '\\\\').replace(/"/g, '\\"')

  return '"' + escaped + '"'
}

// convert a JS array to a postgres array literal
// uses comma separator so won't work for types like box that use
// a different array separator.
function arrayString(val) {
  var result = '{'
  for (var i = 0; i < val.length; i++) {
    if (i > 0) {
      result = result + ','
    }
    if (val[i] === null || typeof val[i] === 'undefined') {
      result = result + 'NULL'
    } else if (Array.isArray(val[i])) {
      result = result + arrayString(val[i])
    } else if (val[i] instanceof Buffer) {
      result += '\\\\x' + val[i].toString('hex')
    } else {
      result += escapeElement(prepareValue(val[i]))
    }
  }
  result = result + '}'
  return result
}

// converts values from javascript types
// to their 'raw' counterparts for use as a postgres parameter
// note: you can override this function to provide your own conversion mechanism
// for complex types, etc...
var prepareValue = function (val, seen) {
  if (val instanceof Buffer) {
    return val
  }
  if (ArrayBuffer.isView(val)) {
    var buf = Buffer.from(val.buffer, val.byteOffset, val.byteLength)
    if (buf.length === val.byteLength) {
      return buf
    }
    return buf.slice(val.byteOffset, val.byteOffset + val.byteLength) // Node.js v4 does not support those Buffer.from params
  }
  if (val instanceof Date) {
    if (defaults.parseInputDatesAsUTC) {
      return dateToStringUTC(val)
    } else {
      return dateToString(val)
    }
  }
  if (Array.isArray(val)) {
    return arrayString(val)
  }
  if (val === null || typeof val === 'undefined') {
    return null
  }
  if (typeof val === 'object') {
    return prepareObject(val, seen)
  }
  return val.toString()
}

function prepareObject(val, seen) {
  if (val && typeof val.toPostgres === 'function') {
    seen = seen || []
    if (seen.indexOf(val) !== -1) {
      throw new Error('circular reference detected while preparing "' + val + '" for query')
    }
    seen.push(val)

    return prepareValue(val.toPostgres(prepareValue), seen)
  }
  return JSON.stringify(val)
}

function pad(number, digits) {
  number = '' + number
  while (number.length < digits) {
    number = '0' + number
  }
  return number
}

function dateToString(date) {
  var offset = -date.getTimezoneOffset()

  var year = date.getFullYear()
  var isBCYear = year < 1
  if (isBCYear) year = Math.abs(year) + 1 // negative years are 1 off their BC representation

  var ret =
    pad(year, 4) +
    '-' +
    pad(date.getMonth() + 1, 2) +
    '-' +
    pad(date.getDate(), 2) +
    'T' +
    pad(date.getHours(), 2) +
    ':' +
    pad(date.getMinutes(), 2) +
    ':' +
    pad(date.getSeconds(), 2) +
    '.' +
    pad(date.getMilliseconds(), 3)

  if (offset < 0) {
    ret += '-'
    offset *= -1
  } else {
    ret += '+'
  }

  ret += pad(Math.floor(offset / 60), 2) + ':' + pad(offset % 60, 2)
  if (isBCYear) ret += ' BC'
  return ret
}

function dateToStringUTC(date) {
  var year = date.getUTCFullYear()
  var isBCYear = year < 1
  if (isBCYear) year = Math.abs(year) + 1 // negative years are 1 off their BC representation

  var ret =
    pad(year, 4) +
    '-' +
    pad(date.getUTCMonth() + 1, 2) +
    '-' +
    pad(date.getUTCDate(), 2) +
    'T' +
    pad(date.getUTCHours(), 2) +
    ':' +
    pad(date.getUTCMinutes(), 2) +
    ':' +
    pad(date.getUTCSeconds(), 2) +
    '.' +
    pad(date.getUTCMilliseconds(), 3)

  ret += '+00:00'
  if (isBCYear) ret += ' BC'
  return ret
}

function normalizeQueryConfig(config, values, callback) {
  // can take in strings or config objects
  config = typeof config === 'string' ? { text: config } : config
  if (values) {
    if (typeof values === 'function') {
      config.callback = values
    } else {
      config.values = values
    }
  }
  if (callback) {
    config.callback = callback
  }
  return config
}

const md5 = function (string) {
  return crypto.createHash('md5').update(string, 'utf-8').digest('hex')
}

// See AuthenticationMD5Password at https://www.postgresql.org/docs/current/static/protocol-flow.html
const postgresMd5PasswordHash = function (user, password, salt) {
  var inner = md5(password + user)
  var outer = md5(Buffer.concat([Buffer.from(inner), salt]))
  return 'md5' + outer
}

module.exports = {
  prepareValue: function prepareValueWrapper(value) {
    // this ensures that extra arguments do not get passed into prepareValue
    // by accident, eg: from calling values.map(utils.prepareValue)
    return prepareValue(value)
  },
  normalizeQueryConfig,
  postgresMd5PasswordHash,
  md5,
}

},
"tVVxm6d79sgDfESoEEFzAHFlVTJ5ohQ7WnNmlFl8BuA=":
function (require, module, exports, __dirname, __filename) {
'use strict'

module.exports = function parseBytea (input) {
  if (/^\\x/.test(input)) {
    // new 'hex' style response (pg >9.0)
    return new Buffer(input.substr(2), 'hex')
  }
  var output = ''
  var i = 0
  while (i < input.length) {
    if (input[i] !== '\\') {
      output += input[i]
      ++i
    } else {
      if (/[0-7]{3}/.test(input.substr(i + 1, 3))) {
        output += String.fromCharCode(parseInt(input.substr(i + 1, 3), 8))
        i += 4
      } else {
        var backslashes = 1
        while (i + backslashes < input.length && input[i + backslashes] === '\\') {
          backslashes++
        }
        for (var k = 0; k < Math.floor(backslashes / 2); ++k) {
          output += '\\'
        }
        i += Math.floor(backslashes / 2) * 2
      }
    }
  }
  return new Buffer(output, 'binary')
}

},
"uGW+o3LS/8tJQqFwXtORD0j410qEDsQMVUhRUFMraPo=":
function (require, module, exports, __dirname, __filename) {
'use strict'
/**
 * Copyright (c) 2010-2017 Brian Carlson (brian.m.carlson@gmail.com)
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * README.md file in the root directory of this source tree.
 */

module.exports = {
  // database host. defaults to localhost
  host: 'localhost',

  // database user's name
  user: process.platform === 'win32' ? process.env.USERNAME : process.env.USER,

  // name of database to connect
  database: undefined,

  // database user's password
  password: null,

  // a Postgres connection string to be used instead of setting individual connection items
  // NOTE:  Setting this value will cause it to override any other value (such as database or user) defined
  // in the defaults object.
  connectionString: undefined,

  // database port
  port: 5432,

  // number of rows to return at a time from a prepared statement's
  // portal. 0 will return all rows at once
  rows: 0,

  // binary result mode
  binary: false,

  // Connection pool options - see https://github.com/brianc/node-pg-pool

  // number of connections to use in connection pool
  // 0 will disable connection pooling
  max: 10,

  // max milliseconds a client can go unused before it is removed
  // from the pool and destroyed
  idleTimeoutMillis: 30000,

  client_encoding: '',

  ssl: false,

  application_name: undefined,

  fallback_application_name: undefined,

  options: undefined,

  parseInputDatesAsUTC: false,

  // max milliseconds any query using this connection will execute for before timing out in error.
  // false=unlimited
  statement_timeout: false,

  // Terminate any session with an open transaction that has been idle for longer than the specified duration in milliseconds
  // false=unlimited
  idle_in_transaction_session_timeout: false,

  // max milliseconds to wait for query to complete (client side)
  query_timeout: false,

  connect_timeout: 0,

  keepalives: 1,

  keepalives_idle: 0,
}

var pgTypes = require('pg-types')
// save default parsers
var parseBigInteger = pgTypes.getTypeParser(20, 'text')
var parseBigIntegerArray = pgTypes.getTypeParser(1016, 'text')

// parse int8 so you can get your count values as actual numbers
module.exports.__defineSetter__('parseInt8', function (val) {
  pgTypes.setTypeParser(20, 'text', val ? pgTypes.getTypeParser(23, 'text') : parseBigInteger)
  pgTypes.setTypeParser(1016, 'text', val ? pgTypes.getTypeParser(1007, 'text') : parseBigIntegerArray)
})

},
"vYEaUwAAUItrkMHbRiB44SLwQEdp1z9XrUH+kKyhWb0=":
function (require, module, exports, __dirname, __filename) {
var array = require('postgres-array')
var arrayParser = require('./arrayParser');
var parseDate = require('postgres-date');
var parseInterval = require('postgres-interval');
var parseByteA = require('postgres-bytea');

function allowNull (fn) {
  return function nullAllowed (value) {
    if (value === null) return value
    return fn(value)
  }
}

function parseBool (value) {
  if (value === null) return value
  return value === 'TRUE' ||
    value === 't' ||
    value === 'true' ||
    value === 'y' ||
    value === 'yes' ||
    value === 'on' ||
    value === '1';
}

function parseBoolArray (value) {
  if (!value) return null
  return array.parse(value, parseBool)
}

function parseBaseTenInt (string) {
  return parseInt(string, 10)
}

function parseIntegerArray (value) {
  if (!value) return null
  return array.parse(value, allowNull(parseBaseTenInt))
}

function parseBigIntegerArray (value) {
  if (!value) return null
  return array.parse(value, allowNull(function (entry) {
    return parseBigInteger(entry).trim()
  }))
}

var parsePointArray = function(value) {
  if(!value) { return null; }
  var p = arrayParser.create(value, function(entry) {
    if(entry !== null) {
      entry = parsePoint(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseFloatArray = function(value) {
  if(!value) { return null; }
  var p = arrayParser.create(value, function(entry) {
    if(entry !== null) {
      entry = parseFloat(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseStringArray = function(value) {
  if(!value) { return null; }

  var p = arrayParser.create(value);
  return p.parse();
};

var parseDateArray = function(value) {
  if (!value) { return null; }

  var p = arrayParser.create(value, function(entry) {
    if (entry !== null) {
      entry = parseDate(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseIntervalArray = function(value) {
  if (!value) { return null; }

  var p = arrayParser.create(value, function(entry) {
    if (entry !== null) {
      entry = parseInterval(entry);
    }
    return entry;
  });

  return p.parse();
};

var parseByteAArray = function(value) {
  if (!value) { return null; }

  return array.parse(value, allowNull(parseByteA));
};

var parseInteger = function(value) {
  return parseInt(value, 10);
};

var parseBigInteger = function(value) {
  var valStr = String(value);
  if (/^\d+$/.test(valStr)) { return valStr; }
  return value;
};

var parseJsonArray = function(value) {
  if (!value) { return null; }

  return array.parse(value, allowNull(JSON.parse));
};

var parsePoint = function(value) {
  if (value[0] !== '(') { return null; }

  value = value.substring( 1, value.length - 1 ).split(',');

  return {
    x: parseFloat(value[0])
  , y: parseFloat(value[1])
  };
};

var parseCircle = function(value) {
  if (value[0] !== '<' && value[1] !== '(') { return null; }

  var point = '(';
  var radius = '';
  var pointParsed = false;
  for (var i = 2; i < value.length - 1; i++){
    if (!pointParsed) {
      point += value[i];
    }

    if (value[i] === ')') {
      pointParsed = true;
      continue;
    } else if (!pointParsed) {
      continue;
    }

    if (value[i] === ','){
      continue;
    }

    radius += value[i];
  }
  var result = parsePoint(point);
  result.radius = parseFloat(radius);

  return result;
};

var init = function(register) {
  register(20, parseBigInteger); // int8
  register(21, parseInteger); // int2
  register(23, parseInteger); // int4
  register(26, parseInteger); // oid
  register(700, parseFloat); // float4/real
  register(701, parseFloat); // float8/double
  register(16, parseBool);
  register(1082, parseDate); // date
  register(1114, parseDate); // timestamp without timezone
  register(1184, parseDate); // timestamp
  register(600, parsePoint); // point
  register(651, parseStringArray); // cidr[]
  register(718, parseCircle); // circle
  register(1000, parseBoolArray);
  register(1001, parseByteAArray);
  register(1005, parseIntegerArray); // _int2
  register(1007, parseIntegerArray); // _int4
  register(1028, parseIntegerArray); // oid[]
  register(1016, parseBigIntegerArray); // _int8
  register(1017, parsePointArray); // point[]
  register(1021, parseFloatArray); // _float4
  register(1022, parseFloatArray); // _float8
  register(1231, parseFloatArray); // _numeric
  register(1014, parseStringArray); //char
  register(1015, parseStringArray); //varchar
  register(1008, parseStringArray);
  register(1009, parseStringArray);
  register(1040, parseStringArray); // macaddr[]
  register(1041, parseStringArray); // inet[]
  register(1115, parseDateArray); // timestamp without time zone[]
  register(1182, parseDateArray); // _date
  register(1185, parseDateArray); // timestamp with time zone[]
  register(1186, parseInterval);
  register(1187, parseIntervalArray);
  register(17, parseByteA);
  register(114, JSON.parse.bind(JSON)); // json
  register(3802, JSON.parse.bind(JSON)); // jsonb
  register(199, parseJsonArray); // json[]
  register(3807, parseJsonArray); // jsonb[]
  register(3907, parseStringArray); // numrange[]
  register(2951, parseStringArray); // uuid[]
  register(791, parseStringArray); // money[]
  register(1183, parseStringArray); // time[]
  register(1270, parseStringArray); // timetz[]
};

module.exports = {
  init: init
};

},
"xT9nq7mah+p1AVEl5xBCcx5MtfZjL98MVaTnPNdbyz8=":
function (require, module, exports, __dirname, __filename) {
var Stream = require('stream')

// through
//
// a stream that does nothing but re-emit the input.
// useful for aggregating a series of changing but not ending streams into one stream)

exports = module.exports = through
through.through = through

//create a readable writable stream.

function through (write, end, opts) {
  write = write || function (data) { this.queue(data) }
  end = end || function () { this.queue(null) }

  var ended = false, destroyed = false, buffer = [], _ended = false
  var stream = new Stream()
  stream.readable = stream.writable = true
  stream.paused = false

//  stream.autoPause   = !(opts && opts.autoPause   === false)
  stream.autoDestroy = !(opts && opts.autoDestroy === false)

  stream.write = function (data) {
    write.call(this, data)
    return !stream.paused
  }

  function drain() {
    while(buffer.length && !stream.paused) {
      var data = buffer.shift()
      if(null === data)
        return stream.emit('end')
      else
        stream.emit('data', data)
    }
  }

  stream.queue = stream.push = function (data) {
//    console.error(ended)
    if(_ended) return stream
    if(data === null) _ended = true
    buffer.push(data)
    drain()
    return stream
  }

  //this will be registered as the first 'end' listener
  //must call destroy next tick, to make sure we're after any
  //stream piped from here.
  //this is only a problem if end is not emitted synchronously.
  //a nicer way to do this is to make sure this is the last listener for 'end'

  stream.on('end', function () {
    stream.readable = false
    if(!stream.writable && stream.autoDestroy)
      process.nextTick(function () {
        stream.destroy()
      })
  })

  function _end () {
    stream.writable = false
    end.call(stream)
    if(!stream.readable && stream.autoDestroy)
      stream.destroy()
  }

  stream.end = function (data) {
    if(ended) return
    ended = true
    if(arguments.length) stream.write(data)
    _end() // will emit or queue
    return stream
  }

  stream.destroy = function () {
    if(destroyed) return
    destroyed = true
    ended = true
    buffer.length = 0
    stream.writable = stream.readable = false
    stream.emit('close')
    return stream
  }

  stream.pause = function () {
    if(stream.paused) return
    stream.paused = true
    return stream
  }

  stream.resume = function () {
    if(stream.paused) {
      stream.paused = false
      stream.emit('resume')
    }
    drain()
    //may have become paused again,
    //as drain emits 'data'.
    if(!stream.paused)
      stream.emit('drain')
    return stream
  }
  return stream
}


},
"ytILIOYxISW0X3RIDro+9GtFaZfaT1O77FY1bWbt1zA=":
function (require, module, exports, __dirname, __filename) {
var array = require('postgres-array');

module.exports = {
  create: function (source, transform) {
    return {
      parse: function() {
        return array.parse(source, transform);
      }
    };
  }
};

},
"zJW472wyqa/cSLhaXnEo1eKVZ/je0C2b96zSfD2HDDk=":
function (require, module, exports, __dirname, __filename) {
'use strict';

var path = require('path')
  , fs = require('fs')
  , helper = require('./helper.js')
;


module.exports = function(connInfo, cb) {
    var file = helper.getFileName();
    
    fs.stat(file, function(err, stat){
        if (err || !helper.usePgPass(stat, file)) {
            return cb(undefined);
        }

        var st = fs.createReadStream(file);

        helper.getPassword(connInfo, st, cb);
    });
};

module.exports.warnTo = helper.warnTo;

},

}
,
{
  "node_modules/bindings/bindings.js": [
    "jjKg038gvW99W9v5nQQaonvkfLvlFyrBPr9zgKELO/Y=",
    {
      "file-uri-to-path": "node_modules/file-uri-to-path/index.js"
    }
  ],
  "node_modules/file-uri-to-path/index.js": [
    "5iKT6HG91adEn/PHlWyVNuwdLqc2lGHedzIrUla7k+c=",
    {}
  ],
  "node_modules/libpq/index.js": [
    "pxUwCL/NaJJErBzfOJVnSSyfoCILL5oPs+x0yEQzx0k=",
    {
      "bindings": "node_modules/bindings/bindings.js"
    }
  ],
  "node_modules/pg-connection-string/index.js": [
    "dYwHlwmLA9EUU1C8Lnbov7Mjg0HCCuvpeSqcpaPpnTY=",
    {}
  ],
  "node_modules/pg-int8/index.js": [
    "+ZGwpBEZvODvu0cSddvQLeMaef5vh/j15WeONzoPFic=",
    {}
  ],
  "node_modules/pg-native/index.js": [
    "bEvcYhHaxxrPXXLYZoF6lPQ4EFQKsNkipsl/yeEz1oM=",
    {
      "./lib/build-result": "node_modules/pg-native/lib/build-result.js",
      "./lib/copy-stream": "node_modules/pg-native/lib/copy-stream.js",
      "./package.json": "node_modules/pg-native/package.json",
      "libpq": "node_modules/libpq/index.js",
      "pg-types": "node_modules/pg-native/node_modules/pg-types/index.js"
    }
  ],
  "node_modules/pg-native/lib/build-result.js": [
    "9QZRF+3tnhRvzr+w/GI0SBAtf/oX1eceqf7y7jLHx2A=",
    {}
  ],
  "node_modules/pg-native/lib/copy-stream.js": [
    "70jB4YCHO+f5+2YiT2GmAT0aL9hAWuwRRtNBIqV4sSc=",
    {}
  ],
  "node_modules/pg-native/node_modules/pg-types/index.js": [
    "RIvK3ye6oQ3hOlekvKk9VaMdlKZ2pWcgxHcNxeV1YdQ=",
    {
      "./lib/arrayParser": "node_modules/pg-native/node_modules/pg-types/lib/arrayParser.js",
      "./lib/binaryParsers": "node_modules/pg-native/node_modules/pg-types/lib/binaryParsers.js",
      "./lib/textParsers": "node_modules/pg-native/node_modules/pg-types/lib/textParsers.js"
    }
  ],
  "node_modules/pg-native/node_modules/pg-types/lib/arrayParser.js": [
    "ytILIOYxISW0X3RIDro+9GtFaZfaT1O77FY1bWbt1zA=",
    {
      "postgres-array": "node_modules/pg-native/node_modules/postgres-array/index.js"
    }
  ],
  "node_modules/pg-native/node_modules/pg-types/lib/binaryParsers.js": [
    "SwEFQUBo6pZFDvDUINuUScAMVlxYlGg5Va8Vv5QHX7k=",
    {
      "pg-int8": "node_modules/pg-int8/index.js"
    }
  ],
  "node_modules/pg-native/node_modules/pg-types/lib/textParsers.js": [
    "Yz4V7Zi/0LCyyLH4upzASkK/vXROUVnQt9dDb04/nbA=",
    {
      "./arrayParser": "node_modules/pg-native/node_modules/pg-types/lib/arrayParser.js",
      "postgres-array": "node_modules/pg-native/node_modules/postgres-array/index.js",
      "postgres-bytea": "node_modules/postgres-bytea/index.js",
      "postgres-date": "node_modules/postgres-date/index.js",
      "postgres-interval": "node_modules/postgres-interval/index.js"
    }
  ],
  "node_modules/pg-native/node_modules/postgres-array/index.js": [
    "WLhtlY//pqJIXU+PEF+xd6lBrTIHW66FaddoMJVdInE=",
    {}
  ],
  "node_modules/pg-native/package.json": [
    "pO4OwnzZqJGhpwHeyji45JH7ZUzNHU/rCUXCdx0xRUA=",
    {}
  ],
  "node_modules/pg-pool/index.js": [
    "dgEfrtkgzKNgI6IwktnAP+4Fi6Fd2e5Zy9aD0dXaU3c=",
    {
      "pg": "node_modules/pg/lib/index.js"
    }
  ],
  "node_modules/pg-protocol/dist/buffer-reader.js": [
    "1Vghz64laF+FchvSchAuGp3d0LL3SDMka6iAYxKOMfU=",
    {}
  ],
  "node_modules/pg-protocol/dist/buffer-writer.js": [
    "bQ727hJ1DdQaysD8qOUgzwZmmLRW4wYnGC64g6zfyUA=",
    {}
  ],
  "node_modules/pg-protocol/dist/index.js": [
    "ivxPzUcGZhHgeKX6RYdXghUBzhJ5MemCxs/8au6lkz0=",
    {
      "./parser": "node_modules/pg-protocol/dist/parser.js",
      "./serializer": "node_modules/pg-protocol/dist/serializer.js"
    }
  ],
  "node_modules/pg-protocol/dist/messages.js": [
    "XFYMk30OzC8qxSuGI1Tec4uUOOs7/oBeowP4PKg2s+4=",
    {}
  ],
  "node_modules/pg-protocol/dist/parser.js": [
    "XDN0KM5b2RnJgq+SMXaX9CFW7ceFtw2MSDBv46+p5GA=",
    {
      "./buffer-reader": "node_modules/pg-protocol/dist/buffer-reader.js",
      "./messages": "node_modules/pg-protocol/dist/messages.js"
    }
  ],
  "node_modules/pg-protocol/dist/serializer.js": [
    "AkmOfzx4Y8E+OaY4gKD82sH04/2+mzHjhar8XxXRDHA=",
    {
      "./buffer-writer": "node_modules/pg-protocol/dist/buffer-writer.js"
    }
  ],
  "node_modules/pg-types/index.js": [
    "7ObVSScLpV0IEmsQyZlzJNgI7oKO8A2tI26E5U2dVW0=",
    {
      "./lib/arrayParser": "node_modules/pg-types/lib/arrayParser.js",
      "./lib/binaryParsers": "node_modules/pg-types/lib/binaryParsers.js",
      "./lib/builtins": "node_modules/pg-types/lib/builtins.js",
      "./lib/textParsers": "node_modules/pg-types/lib/textParsers.js"
    }
  ],
  "node_modules/pg-types/lib/arrayParser.js": [
    "ytILIOYxISW0X3RIDro+9GtFaZfaT1O77FY1bWbt1zA=",
    {
      "postgres-array": "node_modules/postgres-array/index.js"
    }
  ],
  "node_modules/pg-types/lib/binaryParsers.js": [
    "SwEFQUBo6pZFDvDUINuUScAMVlxYlGg5Va8Vv5QHX7k=",
    {
      "pg-int8": "node_modules/pg-int8/index.js"
    }
  ],
  "node_modules/pg-types/lib/builtins.js": [
    "CSExl+S0QBLkyDZpqoCIShiekMd33f7x9EyQxBIWc1Q=",
    {}
  ],
  "node_modules/pg-types/lib/textParsers.js": [
    "vYEaUwAAUItrkMHbRiB44SLwQEdp1z9XrUH+kKyhWb0=",
    {
      "./arrayParser": "node_modules/pg-types/lib/arrayParser.js",
      "postgres-array": "node_modules/postgres-array/index.js",
      "postgres-bytea": "node_modules/postgres-bytea/index.js",
      "postgres-date": "node_modules/postgres-date/index.js",
      "postgres-interval": "node_modules/postgres-interval/index.js"
    }
  ],
  "node_modules/pg/lib/client.js": [
    "DTPuMih+7PorANabFCgekfW6WljofT8j7Ihib2u4LYA=",
    {
      "./connection": "node_modules/pg/lib/connection.js",
      "./connection-parameters": "node_modules/pg/lib/connection-parameters.js",
      "./defaults": "node_modules/pg/lib/defaults.js",
      "./query": "node_modules/pg/lib/query.js",
      "./sasl": "node_modules/pg/lib/sasl.js",
      "./type-overrides": "node_modules/pg/lib/type-overrides.js",
      "./utils": "node_modules/pg/lib/utils.js",
      "pgpass": "node_modules/pgpass/lib/index.js"
    }
  ],
  "node_modules/pg/lib/connection-parameters.js": [
    "+HSmI+SqU2xLFtIyb1L+SgZI9uF1S4iwpXKqdubj0W0=",
    {
      "./defaults": "node_modules/pg/lib/defaults.js",
      "pg-connection-string": "node_modules/pg-connection-string/index.js"
    }
  ],
  "node_modules/pg/lib/connection.js": [
    "I1xz65sqILWF2s9y63OiY4KrT0k9dUNRFt8poUBizpo=",
    {
      "pg-protocol": "node_modules/pg-protocol/dist/index.js"
    }
  ],
  "node_modules/pg/lib/defaults.js": [
    "uGW+o3LS/8tJQqFwXtORD0j410qEDsQMVUhRUFMraPo=",
    {
      "pg-types": "node_modules/pg-types/index.js"
    }
  ],
  "node_modules/pg/lib/index.js": [
    "+uyHj7tA8xmRjCjRC3KUOBJMM3Xd1+Nlzejd1JiM6yQ=",
    {
      "./client": "node_modules/pg/lib/client.js",
      "./connection": "node_modules/pg/lib/connection.js",
      "./defaults": "node_modules/pg/lib/defaults.js",
      "./native": "node_modules/pg/lib/native/index.js",
      "pg-pool": "node_modules/pg-pool/index.js",
      "pg-types": "node_modules/pg-types/index.js"
    }
  ],
  "node_modules/pg/lib/native/client.js": [
    "TuV/D5G5BMyqyNQRKoDarnEwAm7ZfXe4H28u6MfTW34=",
    {
      "../../package.json": "node_modules/pg/package.json",
      "../connection-parameters": "node_modules/pg/lib/connection-parameters.js",
      "../type-overrides": "node_modules/pg/lib/type-overrides.js",
      "./query": "node_modules/pg/lib/native/query.js",
      "pg-native": "node_modules/pg-native/index.js",
      "semver": "node_modules/semver/semver.js"
    }
  ],
  "node_modules/pg/lib/native/index.js": [
    "mfthy3im14t6X8C5rCZK1YJyr0i+S8UL/blIsTQuMpI=",
    {
      "./client": "node_modules/pg/lib/native/client.js"
    }
  ],
  "node_modules/pg/lib/native/query.js": [
    "OpYE+gjRDHgWmbmbYMiYBFbrNQ1rtpSOdapBN5V5QCI=",
    {
      "../utils": "node_modules/pg/lib/utils.js"
    }
  ],
  "node_modules/pg/lib/query.js": [
    "R91Lsu07fk64EFXt6fo+Y55EDmDIi3vNhjQgZDBFFPs=",
    {
      "./result": "node_modules/pg/lib/result.js",
      "./utils": "node_modules/pg/lib/utils.js"
    }
  ],
  "node_modules/pg/lib/result.js": [
    "Q2u38e+JIad5ptjmaF+X3r88pEJOgkrlSngFoN/M+vU=",
    {
      "pg-types": "node_modules/pg-types/index.js"
    }
  ],
  "node_modules/pg/lib/sasl.js": [
    "7/q1fgHGlRmV1IMIe6M6pIR1CHQHq3LTxs93+1FFivQ=",
    {}
  ],
  "node_modules/pg/lib/type-overrides.js": [
    "6UGxUZF8AC3LwJ280/cz8J/u6IvLpB+uB0ovcMwycsM=",
    {
      "pg-types": "node_modules/pg-types/index.js"
    }
  ],
  "node_modules/pg/lib/utils.js": [
    "qffaFyIlqe0KpTmg1FdGSsiUKiEXeLQA9jQMuv99JF8=",
    {
      "./defaults": "node_modules/pg/lib/defaults.js"
    }
  ],
  "node_modules/pg/package.json": [
    "+i8bLWxSsnBNAWTDA9N82doCAwqCkHZLeUvNj8UmodI=",
    {}
  ],
  "node_modules/pgpass/lib/helper.js": [
    "Q3YhfRCTS9t32Y5HDxsZ0Q/qZLvglEG8WnY5U65+78g=",
    {
      "split": "node_modules/split/index.js"
    }
  ],
  "node_modules/pgpass/lib/index.js": [
    "zJW472wyqa/cSLhaXnEo1eKVZ/je0C2b96zSfD2HDDk=",
    {
      "./helper.js": "node_modules/pgpass/lib/helper.js"
    }
  ],
  "node_modules/postgres-array/index.js": [
    "gHulgO1CPlGGcsJ7QCKlastpO+BDSXM//B/m8yT7zuI=",
    {}
  ],
  "node_modules/postgres-bytea/index.js": [
    "tVVxm6d79sgDfESoEEFzAHFlVTJ5ohQ7WnNmlFl8BuA=",
    {}
  ],
  "node_modules/postgres-date/index.js": [
    "o+w5yxsBUAN7YU9TURngynJtL7CrEHeDiIo22OKkZrM=",
    {}
  ],
  "node_modules/postgres-interval/index.js": [
    "g2/go55S8FHWJYPYN107JwtMuT3QJrElQ4qJ5aAljEE=",
    {
      "xtend/mutable": "node_modules/xtend/mutable.js"
    }
  ],
  "node_modules/semver/semver.js": [
    "OaXwRLrzssGfkVjQKKSRdOsA0eDbq+rm69mBs1V9X9Q=",
    {}
  ],
  "node_modules/split/index.js": [
    "dEm6mZ1Ft7Wp+LxXZ4tBQ9lKGyzKvYRWqaIWPrWvDus=",
    {
      "through": "node_modules/through/index.js"
    }
  ],
  "node_modules/through/index.js": [
    "xT9nq7mah+p1AVEl5xBCcx5MtfZjL98MVaTnPNdbyz8=",
    {}
  ],
  "node_modules/xtend/mutable.js": [
    "caOGScd0CCF0g/gfVdruHWZG1sZw49A0pEgss0U4huk=",
    {}
  ],
  "server-dist/server.js": [
    "exLo+LL6iEtcMQDRgCxeR5HkEQnrj5TbqHESoitLZgg=",
    {
      "pg": "node_modules/pg/lib/index.js"
    }
  ]
},
"server-dist/server.js")