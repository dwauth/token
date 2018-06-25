var assert = require('assert')
var jwt = require('jsonwebtoken')
var sublevel = require('subleveldown')
var through = require('@dwcore/dws2')

/**
* Initialize the `dwidToken` module. You can choose to specify either `secret` or `publicKey` and `privateKey` for signatures. To generate a keypair you can use [these commands](https://gist.github.com/maxogden/62b7119909a93204c747633308a4d769).
* @name dwidToken
* @param {object} db – An instance of a leveldb via [level](https://https://github.com/Level/level)
* @param {object} options
* @param {string} options.algorithm – **Optional.** JWA algorithm, default is `HS256` (HMAC/SHA256 with secret). You must specify your key type if using a keypair.
* @param {string} options.secret – **Optional.** Secret used for signing and verifying tokens
* @param {string} options.publicKey – **Optional.** Public key used to sign tokens
* @param {string} options.privateKey – **Optional.** Private key used to verify tokens

* @example
* // using a secret
* var level = require('level')
* var dwidToken = require('@dwauth/token')
*
* var db = level('./db')
* var tokens = dwidToken(db, { secret: process.env.DWID_SECRET })
*
* @example
* // using a keypair
* var tokens = dwidToken(db, {
*   algorithm: 'ES512',
*   public: `-----BEGIN PUBLIC KEY-----
* blahblah
* -----END PUBLIC KEY-----`,
*   private: `-----BEGIN EC PRIVATE KEY-----
* blahblah
* -----END EC PRIVATE KEY-----`
* })
**/

module.exports = function dwidToken (maindb, options) {
  options = options || {}
  var secret = options.secret
  var publicKey = options.publicKey
  var privateKey = options.privateKey
  var algorithm = options.algorithm
  var db = sublevel(maindb, '@dwauth/token')
  var tokens = {}
  tokens.db = db

  /**
  * Sign a payload to create a token.
  * @name tokens.sign
  * @param {object} payload
  * @param {object} payload.auth - The data from the [dwid-auth](https://github.com/dwid/dwid-auth) module for a user
  * @param {object} payload.access - The data from the [dwid-access](https://github.com/dwid/dwid-access) module for a user
  * @param {object} payload.data – Arbitrary data related to the user.
  * @param {object} options - **Optional.**
  * @param {string} options.secret – **Optional.** Override the secret passed into `dwidToken`
  * @param {string} options.expiresIn – **Optional.** _Default:_ `5h`. Specify when the token expires. Uses the [ms](https://github.com/zeit/ms) module.
  * @example
  * var token = tokens.sign({
  *   auth: { basic: { key: 'example', email: 'email@example.com' } },
  *   access: { scopes: ['site:read', 'site:edit'] },
  *   data: { arbitrary: 'data' }
  * })
  **/
  tokens.sign = function sign (payload, options) {
    assert.equal(typeof payload, 'object', 'dwid-token: payload object is required')
    assert.equal(typeof payload.auth, 'object', 'dwid-token: payload.auth object is required')
    assert.equal(typeof payload.access, 'object', 'dwid-token: payload.access object is required')

    options = options || {}
    options.expiresIn = options.expiresIn || '5h'
    if (algorithm) options.algorithm = algorithm
    var secretOrPrivateKey = options.secret || secret
    if (privateKey) secretOrPrivateKey = privateKey
    return jwt.sign(payload, secretOrPrivateKey, options)
  }

  /**
  * Verify a token.
  * @name tokens.verify
  * @param {string} token - The encoded token that was created by `tokens.sign`.
  * @param {object} options - **Optional.**
  * @param {string} options.secret - **Optional.** Override the secret passed into `dwidToken`
  * @param {function} callback
  **/
  tokens.verify = function verify (token, options, callback) {
    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    assert.equal(typeof callback, 'function', 'dwid-token: callback function is required')
    if (!(typeof token === 'string')) return callback(new Error('dwid-token: token parameter must be a string'))

    options = options || {}
    if (algorithm) options.algorithm = algorithm
    var secretOrPublicKey = options.secret || secret
    if (publicKey) secretOrPublicKey = publicKey

    try {
      var data = jwt.verify(token, secretOrPublicKey, options)
      db.get(token, function (err) {
        if (!err) return callback(new Error('Token is invalid'))
        return callback(null, data)
      })
    } catch (jwterr) {
      callback(jwterr)
    }
  }

  /**
  * Invalidate a token by storing it in the invalid list.
  * @name tokens.invalidate
  * @param {string} token - The encoded token that was created by `tokens.sign`.
  * @param {function} callback
  **/
  tokens.invalidate = function invalidate (token, callback) {
    assert.equal(typeof callback, 'function', 'dwid-token: callback function is required')
    if (!(typeof token === 'string')) return callback(new Error('dwid-token: token parameter must be a string'))
    db.put(token, token, callback)
  }

  /**
  * Remove expired tokens from the list of invalid tokens.
  * @name tokens.cleanupInvalidList
  * @param {object} options - **Optional.**
  * @param {string} options.secret - **Optional.** Override the secret passed into `dwidToken`
  * @param {function} callback
  **/
  tokens.cleanupInvalidList = function cleanupInvalidList (options, callback) {
    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    options = options || {}
    if (algorithm) options.algorithm = algorithm
    var secretOrPublicKey = options.secret || secret
    if (publicKey) secretOrPublicKey = publicKey

    db.createReadStream().pipe(through.obj(each, end))

    function each (token, enc, next) {
      try {
        jwt.verify(token.key, secretOrPublicKey, options)
      } catch (jwterr) {
        return db.del(token.key, function (err) {
          if (err) return callback(err)
          next()
        })
      }
      this.push(token)
      next()
    }

    function end () {
      callback()
    }
  }

  return tokens
}
