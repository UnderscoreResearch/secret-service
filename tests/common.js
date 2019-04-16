'use strict';

const test = require('unit.js');
const nacl = require('tweetnacl');

const common = require('../src/common.js');
const s3mock = require('./s3mock.js');
const secretHelper = require('./secrethelper.js');

common.setS3Client(s3mock);

describe('Common', function() {
  it('createMessage', function(done) {
    test.string(common.createMessage("test").message).match(/^test$/);
    done();
  });

  it('encode decode', function(done) {
    var encoded = common.encodeBin("test data");
    var decoded = common.decodeBin(encoded).toString();

    test.value(decoded).is("test data");
    done();
  });

  it('decode number', function(done) {
    var decoded = common.decodeBin(12345).toString();

    test.value(decoded).exists();
    done();
  });

  it('decode invalid', function(done) {
    var decoded = common.decodeBin("^" + common.encodeBin("abc")).toString();

    test.value(decoded).is("abc");
    done();
  });

  it('encode size correct', function(done) {
    var encoded = common.encodeBin("test data");
    var decoded = common.decodeBin(encoded, 9).toString();

    test.value(decoded).is("test data");
    done();
  });

  it('encode size wrong', function(done) {
    var encoded = common.encodeBin("test data");
    var decoded = common.decodeBin(encoded, 8);

    test.value(decoded).isNull();
    done();
  });
  
  it('decodeAuth valid', function(done) {
    var origAuth = {
      t: Date.now(),
      s: "abc",
      method: 'POST',
      url: '/test'
    };
    var req = {
      get: function(name) {
        if (name == "x-yoursharedsecret-ownership") {
          return common.encodeBin(JSON.stringify(origAuth));
        }
      },
      url: '/test',
      method: 'POST'
    };
    var auth = common.decodeAuth(req);
    test.value(auth).is(origAuth);
    done();
  });

  it('decodeAuth invalid', function(done) {
    var req = {
      get: function(name) {
        if (name == "x-yoursharedsecret-ownership") {
          return "doh!";
        }
      },
      uri: '/test',
      method: 'POST'
    };
    var auth = common.decodeAuth(req);
    test.value(auth).isNull();
    done();
  });

  it('get put s3 file', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc", "test data", null, function(err, data) {
      if (err) {
        done(err);
      }
      else {
        common.getS3File("/abc", function(err, data) {
          if (err) {
            done(err);
          }
          else {
            test.value(data.Body.toString()).is("test data");
            test.value(s3mock.getFiles()["/abc"].Body.toString()).isNot("test data");
            done();
          }
        });
      }
    });
  });

  it('get failure', function(done) {
    s3mock.setFiles(null);
    common.putS3File("/abc", "test data", null, function(err) {
      test.value(err).exists();
      done();
    });
  });

  it('put failure', function(done) {
    s3mock.setFiles(null);
    common.putS3File("/abc", "test data", null, function(err) {
      test.value(err).exists();
      done();
    });
  });

  it('deleteS3Files successful', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.putS3File("/abc/gef", "test data", null, function(err) {
          if (err)
            done(err);
          else
            common.putS3File("/def", "test data", null, function(err) {
              if (err)
                done(err);
              else
                common.deleteS3Files("/abc", function(err, data) {
                  test.value(Object.keys(s3mock.getFiles()).length).is(1);
                  test.value(s3mock.getFiles()["/def"]).exists();
                  done(err);
                });
            });
        });
    });
  });

  it('deleteS3Files nothing', function(done) {
    s3mock.setFiles({});
    common.putS3File("/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.deleteS3Files("/abc", function(err, data) {
          test.value(Object.keys(s3mock.getFiles()).length).is(1);
          test.value(s3mock.getFiles()["/def"]).exists();
          done(err);
        });
    });
  });

  it('deleteS3Files failure', function(done) {
    s3mock.setFiles(null);
    common.deleteS3Files("/abc", function(err, data) {
      test.value(err).exists();
      done();
    });
  });
  
  it('validateOwnership valid', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(publicKey);
        done();
      });
    })
    
  });
  
  it('validateOwnership secondValid', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    var otherKey = nacl.sign.keyPair();
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership([common.encodeBin(otherKey.publicKey), publicKey], common.decodeAuth(auth), function (valid) {
        test.value(valid).is(publicKey);
        done();
      });
    })
  });
  
  it('validateOwnership invalidSignature', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    var otherKey = nacl.sign.keyPair();
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership([common.encodeBin(otherKey.publicKey), null], common.decodeAuth(auth), function (valid) {
        test.value(valid).is(null);
        done();
      });
    })
  });

  it('validateOwnership too late', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(null);
        done();
      });
    }, 61 * 1000)
  });

  it('validateOwnership too early', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(null);
        done();
      });
    }, -61 * 1000)
  });

  it('validateOwnership slightly late', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(publicKey);
        done();
      });
    }, 30 * 1000)
  });

  it('validateOwnership slightly early', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(publicKey);
        done();
      });
    }, -30 * 1000)
  });

  it('validateOwnership non number timestamp', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    secretHelper.createAuth(privateKey, "POST", "/", function(auth, publicKey) {
      common.validateOwnership(publicKey, common.decodeAuth(auth), function (valid) {
        test.value(valid).is(null);
        done();
      });
    }, "doh")
  });

  it('validateOwnership missing signature', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    common.validateOwnership("publicKey", { t: Date.now().toString() }, function (valid) {
        test.value(valid).is(null);
        done();
    });
  });

  it('validateOwnership missing timestamp', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    common.validateOwnership("publicKey", { s: Date.now().toString() }, function (valid) {
        test.value(valid).is(null);
        done();
    });
  });

  it('validateOwnership invalid timestamp', function(done) {
    var privateKey = nacl.sign.keyPair().secretKey;
    common.validateOwnership("publicKey", { t: Date.now() }, function (valid) {
        test.value(valid).is(null);
        done();
    });
  });
  
  it('listS3Files successful', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.putS3File("/abc/gef", "test data", null, function(err) {
          if (err)
            done(err);
          else
            common.putS3File("/def", "test data", null, function(err) {
              if (err)
                done(err);
              else
                common.listS3Files("/abc/", function(err, data) {
                  test.value(data).is(["/abc/def", "/abc/gef"]);
                  done(err);
                });
            });
        });
    });
  });
  
  it('listS3Files nothing', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.listS3Files("/def/", function(err, data) {
          test.value(data).is([]);
          done(err);
        });
    });
  });
  
  it('listS3Files error', function(done) {
    s3mock.setFiles(null);
      common.listS3Files("/def/", function(err, data) {
        test.value(err).exists();
        done();
      });
  });
  
  it('listS3Files empty', function(done) {
    s3mock.setFiles({});
    common.listS3Files("/abc/", function(err, data) {
      test.value(data).is([]);
      done(err);
    });
  });
  
  it('listS3Children successful', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.putS3File("/abc/gef", "test data", null, function(err) {
          if (err)
            done(err);
          else
            common.putS3File("/def", "test data", null, function(err) {
              if (err)
                done(err);
              else
                common.listS3Children("/abc/", function(err, data) {
                  test.value(data).is(["def", "gef"]);
                  done(err);
                });
            });
        });
    });
  });
  
  it('listS3Children nothing', function(done) {
    s3mock.setFiles({});
    common.putS3File("/abc/def", "test data", null, function(err) {
      if (err)
        done(err);
      else
        common.listS3Children("/def/", function(err, data) {
          test.value(data).is([]);
          done(err);
        });
    });
  });
  
  it('listS3Children error', function(done) {
    s3mock.setFiles(null);
      common.listS3Children("/def/", function(err, data) {
        test.value(err).exists();
        done();
      });
  });
  
  it('listS3Children empty', function(done) {
    s3mock.setFiles({});
    common.listS3Children("/abc/", function(err, data) {
      test.value(data).is([]);
      done(err);
    });
  });

  var signingKey = nacl.sign.keyPair().secretKey;
  var publicKey = nacl.sign.keyPair.fromSecretKey(signingKey).publicKey;
  var otherSigningKey = nacl.sign.keyPair().secretKey;
  var otherPublic = nacl.sign.keyPair.fromSecretKey(otherSigningKey).publicKey;
  var encryptionKey = nacl.randomBytes(32);
  var message = Buffer.from("Message", 'utf8');
  var expected = Uint8Array.from(message);
  
  it('decrypt/encrypt clearText', function(done) {
    var encrypted = secretHelper.encodeEncryptedSymmetric(message, signingKey);
    test.value(secretHelper.decodeEncrypted(encrypted, publicKey).toString()).is(message.toString());
    test.value(common.decodeEncryptedEnvelope(encrypted).message.toString()).is(message.toString());
    test.value(common.validateEncryption(encrypted, publicKey)).is(true);
    test.value(common.validateEncryption(encrypted, otherPublic)).is(false);
    done();
  })
  
  it('decrypt/encrypt privateKey ephemeral', function(done) {
    var encrypted = secretHelper.encodeEncryptedAsymmetric(message, signingKey, publicKey);
    test.value(secretHelper.decodeEncrypted(encrypted, publicKey, signingKey)).is(expected);
    test.value(common.decodeEncryptedEnvelope(encrypted).message).isNot(expected);
    test.value(common.validateEncryption(encrypted, publicKey)).is(true);
    test.value(common.validateEncryption(encrypted, otherPublic)).is(false);
    done();
  })

  it('decrypt/encrypt dataKey', function(done) {
    var encrypted = secretHelper.encodeEncryptedSymmetric(message, signingKey, encryptionKey);
    test.value(secretHelper.decodeEncrypted(encrypted, publicKey, encryptionKey)).is(expected);
    test.value(common.decodeEncryptedEnvelope(encrypted).message).isNot(expected);
    test.value(common.validateEncryption(encrypted, publicKey)).is(true);
    test.value(common.validateEncryption(encrypted, otherPublic)).is(false);
    done();
  })

});
