var _ = require('underscore'),
    async = require('async'),
    events = require('events'),
    https = require('https'),
    sinon = require('sinon'),
    should = require('should'),
    util = require('util');

var validator = require('../lib/validator');

/*
 * private/public key pair generated with openssl:
 * $ openssl genrsa -out privateKey.pem 1024
 * $ openssl rsa -in privateKey.pem -pubout -out publicKey.pem
 */
var privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICXgIBAAKBgQC785KChPYGtmVCsoaDiIrYI2bhvcG+L8iy2srxm98v4HD8v2ip\n' +
  'bKSmqMSCS9m9lFd+B2C9dp4EsEvwJUwW86dRax/DqhXl/HwrU2aHNqSBdJnMfVjX\n' +
  'ZTYfN9nRz6WmKcKfreDe7+TIeBTVJJeN68p4IIEAFH7tszC+rk7+pzTQcQIDAQAB\n' +
  'AoGBAINwq50rbwLyu44RW5DRBIhy+ZgVJFDlCe5KpHKjF0pcI6geFAuoNt12WTbl\n' +
  '5Lh37VftwPG+6nNM905SRwwmCXPsE42/D32NSe136Ly2zqRa7vJSHvF83g/WlCxR\n' +
  'Ggaaf3LiGWQ0+fj4A0CW24qvVx8ZrkE0tNnl0fFIE6uLWikhAkEA4Wi8wOxfUqB+\n' +
  'VK8rsOBXFgUI82lkX9v8TVcZJRssCjurCbxiwn1cUgnFA54gXuAyLZiyyaDKGVSF\n' +
  'kxb4E67tFwJBANV1dsmKbAEs5cd+5QVHQOHB9KQ/akk7JLjjUGMCdS67Hhmj2Lqe\n' +
  'WgpFMdqpbutp5vG3OMP5ieojO4IOUH2Yc7cCQFBLD9mlGXuEYhvmXijecQcN+hdC\n' +
  '9pdS9HfUS8e0+yYWBSItsfxXzXgHtN9KB3vkXttxJla+aN9HBWHU77+LMzcCQQDE\n' +
  'LhjmUdnBmsnz96P0ne/7jI6TBdVhSIIPipsu4+te74pSdkuR+Ec4eS/Aj0fqBILE\n' +
  'VGhPdOBT192xQgan550xAkEAqA4fUIlSUcbGcOISYHGeNgCcjCaQi7fHSQpdlacb\n' +
  'VRUtTonrAGeaPDfIeVXqtjP49bag14uPbRNu1N9Rss1X8g==\n' +
  '-----END RSA PRIVATE KEY-----\n';

var publicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC785KChPYGtmVCsoaDiIrYI2bh\n' +
  'vcG+L8iy2srxm98v4HD8v2ipbKSmqMSCS9m9lFd+B2C9dp4EsEvwJUwW86dRax/D\n' +
  'qhXl/HwrU2aHNqSBdJnMfVjXZTYfN9nRz6WmKcKfreDe7+TIeBTVJJeN68p4IIEA\n' +
  'FH7tszC+rk7+pzTQcQIDAQAB\n' +
  '-----END PUBLIC KEY-----';

// Arbitrarily selected string.
var publicKeyId = 'aa9fe7955aa950a526b9655b5300caae8edadcc8';

// Use sinon's sandbox feature for easy cleanup of fakes.
// Note: MUST use 'this.sandbox' in all tests, as opposed to the required() 'sinon' object.
beforeEach(function() {
  this.sandbox = sinon.sandbox.create();
});
afterEach(function() {
  this.sandbox.restore();
});

describe('Tests the JSON Web Token encoder and decoder', function() {
  var defaultClaimsSet = {
    id: 'test1234',
    email: 'roman.khmelichek@gmail.com'
  };

  var defaultPubKeyReqOpts = {
    host: 'www.googleapis.com',
    path: '/oauth2/v1/certs'
  };

  beforeEach(function() {
  });

  afterEach(function() {
    validator.clearPublicKeyCache();
  });

  it('successfully decodes a JWT when the public key endpoint returns a valid, successful response', function(done) {
    // Stub the request to retrieve the public key.
    this.sandbox.stub(https, 'request', function(options, cb) {
      var response = new events.EventEmitter();
      response.statusCode = 200;
      response.setEncoding = function() {};

      var pubKeyResJson = { 'dummyId': 'dummy public key' };
      pubKeyResJson[publicKeyId] = publicKey;

      cb(response);
      response.emit('data', JSON.stringify(pubKeyResJson));
      response.emit('end');

      return {
        on: function() {},
        end: function() {}
      }
    });

    var encodedJwt = validator.encode(privateKey, publicKeyId, defaultClaimsSet);
    validator.decode(encodedJwt, defaultPubKeyReqOpts, function(err, decodedJwt) {
      if (err == null) {
        should.exist(decodedJwt);
        decodedJwt.should.have.property('id', defaultClaimsSet.id);
        decodedJwt.should.have.property('email', defaultClaimsSet.email);

        // Verify that the stubbed method was called.
        https.request.calledWith().should.be.ok;

        done();
      } else {
        done(err);
      }
    });
  });

  it('caches the public keys returned from the public key endpoint', function(done) {
    // Stub the request to retrieve the public key.
    this.sandbox.stub(https, 'request', function(options, cb) {
      var response = new events.EventEmitter();
      response.statusCode = 200;
      response.setEncoding = function() {};

      var pubKeyResJson = { 'dummyId': 'dummy public key' };
      pubKeyResJson[publicKeyId] = publicKey;

      cb(response);
      response.emit('data', JSON.stringify(pubKeyResJson));
      response.emit('end');

      return {
        on: function() {},
        end: function() {}
      }
    });

    var encodedJwt = validator.encode(privateKey, publicKeyId, defaultClaimsSet);

    // Call the decoder multiple times, so we can verify we retrieved the public keys only once.
    async.series([
      function(callback) {
        validator.decode(encodedJwt, defaultPubKeyReqOpts, function(err, decodedJwt) {
          if (err == null) {
            callback(null, decodedJwt);
          } else {
            callback(err);
          }
        });
      },
      function(callback) {
        validator.decode(encodedJwt, defaultPubKeyReqOpts, function(err, decodedJwt) {
          if (err == null) {
            callback(null, decodedJwt);
          } else {
            callback(err);
          }
        });
      }
    ],
    function(err, results) {
      if (err == null) {
        should.exist(results);
        results.should.have.lengthOf(2);

        results[0].should.have.property('id', defaultClaimsSet.id);
        results[0].should.have.property('email', defaultClaimsSet.email);

        // Deep equal.
        results[0].should.eql(results[1]);

        // Verify that the stubbed method was called only once.
        https.request.calledWith().should.be.ok;
        https.request.callCount.should.equal(1);

        done();
      } else {
        done(err);
      }
    });
  });
});
