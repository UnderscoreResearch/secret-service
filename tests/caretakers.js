'use strict';

const test = require('unit.js');
const common = require('../src/common.js');
const caretakers = require('../src/caretakers.js');
const secretHelper = require('./secrethelper.js');
const nacl = require('tweetnacl');
const caretakerHelper = require("./caretakerhelper");

describe('Caretakers', function() {
  var privateKey = nacl.sign.keyPair().secretKey;
  var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;
  var dataKey = nacl.randomBytes(32);
  
  it('success', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr1) {
      caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr2) {
        caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr3) {
          caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr4) {
            caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr5) {
              caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr6) {
                caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr7) {
                  caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr8) {
                    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr9) {
                      caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr10) {
                        caretakers.validateAddresses(publicKey, [ addr1, addr2, addr3, addr4, addr5, addr6, addr7, addr8, addr9, addr10 ], function(err) {
                          done(err);
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
  
  it('success undef', function(done) {
    var addr;
    caretakers.validateAddresses(publicKey, addr, function(err) {
      done(err);
    });
  });

  it('success null', function(done) {
    caretakers.validateAddresses(publicKey, null, function(err) {
      done(err);
    });
  });
  
  it('success empty', function(done) {
    caretakers.validateAddresses(publicKey, [], function(err) {
      done(err);
    });
  });
  
  it('success unencrypted', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        test.value(secretHelper.decodeEncrypted(addr.address, publicKey).toString()).is("address@example.com");
        done(err);
      })
    });
  });
  
  it('success exactlly address', function(done) {
    var address = "1";
    for (var i = 0; i < 680; i++) {
      address += "1";
    }
    caretakerHelper.createCorrectAddress(privateKey, null, address, function(addr) {
      if (addr.address.length < 998) {
        throw new Error("Address too short: " + addr.address.length);
      }
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(err);
      })
    });
  });
  
  it('invalid address too long', function(done) {
    var address = "1";
    for (var i = 0; i < 682; i++) {
      address += "1";
    }
    caretakerHelper.createCorrectAddress(privateKey, null, address, function(addr) {
      if (addr.address.length > 1002) {
        throw new Error("Address too short: " + addr.address.length);
      }
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('invalid signature unencrypted', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
      caretakers.validateAddresses(nacl.sign.keyPair().publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('invalid signature', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      caretakers.validateAddresses(nacl.sign.keyPair().publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('missing addressDigest', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      delete addr["addressDigest"];
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('invalid addressDigest', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      addr["addressDigest"] = "abc";
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('missing address', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      delete addr["address"];
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('missing addressType', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      delete addr["addressType"];
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('invalid addressType', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      addr["addressType"] = 'DOH';
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('invalid address', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr) {
      addr["address"] = "abc";
      caretakers.validateAddresses(publicKey, [ addr ], function(err) {
        done(!err);
      })
    });
  });
  
  it('too many addresses', function(done) {
    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr1) {
      caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr2) {
        caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr3) {
          caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr4) {
            caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr5) {
              caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr6) {
                caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr7) {
                  caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr8) {
                    caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr9) {
                      caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr10) {
                        caretakerHelper.createCorrectAddress(privateKey, dataKey, "address@example.com", function(addr11) {
                          caretakers.validateAddresses(publicKey, [ addr1, addr2, addr3, addr4, addr5, addr6, addr7, addr8, addr9, addr10, addr11 ], function(err) {
                            done(!err);
                          })
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
  
  it('preparedResponseCaretaker stripAll', function(done) {
     var testValue = {
       addressKeyDigest: 'something',
       addresses: [
         {
           addressDigest: 'something'
         },
         {
           addressDigest: 'something'
         }
       ]
     };
     caretakers.preparedResponseCaretaker(testValue, {
       publicKey: 'key'
     });
     test.value(testValue).is({
       addresses: [{}, {}],
       secretPublicKey: 'key'
     });
     done();
  });
  
  it('preparedResponseCaretaker propagate unlock', function(done) {
     var testValue = {
     };
     caretakers.preparedResponseCaretaker(testValue, {
       unlockPublicKey: 'test',
       publicKey: 'key'
     });
     test.value(testValue).is({
       unlockPublicKey: 'test',
       secretPublicKey: 'key'
     });
     done();
  });
  
  it('preparedResponseCaretaker remove incorrect unlock', function(done) {
     var testValue = {
       unlockPublicKey: 'other',
       unlockData: 'data'
     };
     caretakers.preparedResponseCaretaker(testValue, {
       unlockPublicKey: 'test',
       publicKey: 'key'
     });
     test.value(testValue).is({
       unlockPublicKey: 'test',
       secretPublicKey: 'key'
     });
     done();
  });
});
