/**
 * Module that handles encoding and decoding (plus validation) of JSON web tokens
 * that are digitally signed using JSON Web Signature (JWS).
 *
 * Tested with Google's OAuth2 web services.
 */
var _ = require('underscore'),
    crypto = require('crypto'),
    https = require('https'),
    util = require('util');

/**
 * Used for caching public keys, with the key being the combination of host, path, and the public key id.
 */
var pubKeyCache = {};

function clearPublicKeyCache() {
  // We clear all properties rather than re-initializing and invalidating the reference.
  // This is important because memoizeAsync() captures the reference to the cache object.
  for (var key in pubKeyCache) {
    delete pubKeyCache[key];
  }
}

/**
 * Inspired by '_.memoize()', except 'memoizeAsync()' handles functions whose result is returned in a callback.
 */
function memoizeAsync(fn, lookupKeyFn, cache) {
  return function() {
    var key = lookupKeyFn(arguments);
    var callback = arguments[arguments.length - 1];

    if (callback == null || !callback instanceof Function) {
      throw new Error('Last argument must be a callback function');
    }

    if (_.has(cache, key)) {
      callback(null, cache[key]);
    } else {
      var memoizedCallback = function(err, retObj) {
        if (err == null)
          cache[key] = retObj;

        callback(err, retObj);
      };
      arguments[arguments.length - 1] = memoizedCallback;
      fn.apply(this, arguments);
    }
  };
}

function retrievePublicKey(pubKeyId, reqOpts, cb) {
  if (reqOpts['host'] == null || reqOpts['path'] == null) {
    return cb(new Error('Missing required options "host" and/or "path"'));
  }

  reqOpts = _.extend({
    port: '443',
    method: 'GET',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }, reqOpts);

  var req = https.request(reqOpts, function(res) {
    if (res.statusCode !== 200) {
      return cb(new Error(util.format('Public key endpoint returned response code: %d', res.statusCode)));
    }

    res.body = '';
    res.setEncoding('utf8');

    res.on('data', function(chunk) {
      res.body += chunk;
    });

    res.on('end', function() {
      try {
        var jsonResponse = JSON.parse(res.body);
      } catch (e) {
        return cb(e);
      }

      cb(null, jsonResponse[pubKeyId]);
    });
  });

  req.on('error', function(err) {
    cb(err);
  });

  req.end();
}

/**
 * Memoized wrapper function around 'retrievePublicKey'.
 */
var retrievePublicKeyCached = memoizeAsync(retrievePublicKey, function(args) {
  var pubKeyId = args[0];
  var reqOpts = args[1];

  return util.format('%s:%s:%s', reqOpts.host, reqOpts.path, pubKeyId);
}, pubKeyCache);

function decode(encodedJwt, pubKeyReqOpts, cb) {
  var components = encodedJwt.split('.');

  // Encoded values.
  var encodedJwtHeader;
  var encodedJwtClaimsSet;
  var encodedJwtSignature;

  // Decoded values.
  var jwtHeader;
  var jwtClaimsSet;

  _.each(components, function(component, idx) {
    var componentBuf = new Buffer(component, 'base64');
    switch (idx) {
      case 0:
        encodedJwtHeader = component;
        jwtHeader = componentBuf.toString('utf8');
        break;

      case 1:
        encodedJwtClaimsSet = component;
        jwtClaimsSet = componentBuf.toString('utf8');
        break;

      case 2:
        encodedJwtSignature = component;
        break;
    }
  });

  var jsonJwtHeader;
  try {
    jsonJwtHeader = JSON.parse(jwtHeader);
  } catch (e) {
    return cb(e);
  }

  if (encodedJwtHeader && encodedJwtClaimsSet && encodedJwtSignature) {
    var rs256 = crypto.createVerify('RSA-SHA256');
    rs256.update(encodedJwtHeader);
    rs256.update('.');
    rs256.update(encodedJwtClaimsSet);

    retrievePublicKeyCached(jsonJwtHeader['kid'], pubKeyReqOpts, function(err, pubKey) {
      if (!err) {
        if (pubKey != null) {
          var valid = rs256.verify(pubKey, encodedJwtSignature, 'base64');
          if (valid) {
            var jsonJwtClaimsSet;
            try {
              jsonJwtClaimsSet = JSON.parse(jwtClaimsSet);
            } catch (e) {
              return cb(e);
            }

            cb(null, jsonJwtClaimsSet);
          } else {
            cb(new Error('Unable to verify JWT'));
          }
        } else {
          // TODO: If no public key matches the public key id, we should attempt to refresh the cache once.
          cb(new Error('Unable to verify JWT - no public key found'));
        }
      } else {
        cb(err);
      }
    });
  } else {
    cb(new Error('Invalid JWT'));
  }
}

function encode(privateKey, pubKeyId, claimsSetObj) {
  var jwtHeader = JSON.stringify({
    'alg': 'RS256',
    'kid': pubKeyId
  });
  var jwtClaimsSet = JSON.stringify(claimsSetObj);

  var encodedJwtHeader = new Buffer(jwtHeader).toString('base64');
  var encodedJwtClaimsSet = new Buffer(jwtClaimsSet).toString('base64');

  var rs256 = crypto.createSign('RSA-SHA256');
  rs256.update(encodedJwtHeader);
  rs256.update('.');
  rs256.update(encodedJwtClaimsSet);

  var encodedJwtSignature = rs256.sign(privateKey, 'base64');

  return encodedJwtHeader + '.' + encodedJwtClaimsSet + '.' + encodedJwtSignature;
}

exports.encode = encode;
exports.decode = decode;
exports.clearPublicKeyCache = clearPublicKeyCache;