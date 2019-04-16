'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');

const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const caretakerHelper = require('./caretakerhelper.js');

common.setS3Client(s3mock);

const request = supertest(app);

function testCaretaker(ind, privateKey, addr, secretId, done) {
    var caretakerId = ind;
    var url = '/caretakers/' + secretId + "/" + caretakerId;
    secretHelper.createAuth(privateKey, "POST", url, function(auth) {
        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(200).end(function(err, result) {
            if (err) {
                if (ind == 16) {
                    done();
                }
                else {
                    done(err);
                }
            }
            else {
                if (ind >= 16) {
                    done("Too many caretakers");
                    return;
                }
                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                    test.value(JSON.parse(data.Body)).is({ addresses: [addr] });
                    if (err) {
                        done(err);
                    }
                    else {
                        testCaretaker(ind + 1, privateKey, addr, secretId, done);
                    }
                });
            }
        });
    });

}

describe('createCaretaker', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));

    it('successful no file', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                test.value(JSON.parse(data.Body)).is({ addresses: [addr] });
                                done(err);
                            });
                        }
                    });
                });
            });
        }, null, null, true);
    });

    it('successful publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            let keyPair = nacl.sign.keyPair();
            const encryptionKey = nacl.box.before(ed2curve.convertPublicKey(keyPair.publicKey),
                ed2curve.convertSecretKey(privateKey));

            caretakerHelper.createCorrectAddress(keyPair.secretKey, encryptionKey, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ publicKey: common.encodeBin(keyPair.publicKey),
                        addresses: [addr] }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                test.value(JSON.parse(data.Body)).is({ publicKey: common.encodeBin(keyPair.publicKey), addresses: [addr] });
                                done(err);
                            });
                        }
                    });
                });
            });
        }, null, null, true);
    });

    it('successful secretData', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    var secretData = secretHelper.encodeEncryptedAsymmetric(common.encodeBin("abc"),
                        privateKey, nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ 
                        addresses: [addr],
                        secretData: secretData,
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                test.value(JSON.parse(data.Body)).is({ 
                                    addresses: [addr],
                                    secretData: secretData
                                });
                                done(err);
                            });
                        }
                    });
                });
            });
        }, null, null, true);
    });

    it('fail secretData size', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    var secretData = "1";
                    for (var i = 0; i < 610; i++) {
                        secretData += "1";
                    }
                    var secretData = secretHelper.encodeEncryptedAsymmetric(secretData, privateKey,
                        nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                    
                    if (secretData.length > 1002) {
                        throw new Error("Too long: " + secretData.length);
                    }
                    
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ 
                        addresses: [addr],
                        secretData: secretData
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            });
        }, null, null, true);
    });

    it('fail no secretDataSignature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ 
                            addresses: [addr],
                            secretData: "abc"
                        }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            });
        }, null, null, true);
    });

    it('fail wrong secretDataSignature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ 
                            addresses: [addr],
                            secretData: "abc",
                            secretDataSignature: "def"
                        }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            });
        }, null, null, true);
    });

    it('fail too large id', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/1234567890123456789012345678901";
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            });
        }, null, null, true);
    });

    it('successful too many caretakers', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                testCaretaker(0, privateKey, addr, secretId, done);
            });
        }, null, null, true);
    });

    it('successful unacked caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                caretakerHelper.createExistingFiles(function() {
                    secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            else {
                                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                                common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                    test.value(JSON.parse(data.Body)).is({ addresses: [addr] });
                                    done(err);
                                });
                            }
                        });
                    });
                }, secretId, caretakerId, privateKey, null, []);
            });
        }, null, null, true);
    });

    it('failed wrong auth', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(nacl.sign.keyPair().secretKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            });
        }, null, null, true);
    });

    it('failed acked caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                caretakerHelper.createExistingFiles(function() {
                    secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, caretakerId, privateKey, null, [], null, true);
            });
        }, null, null, true);
    });

    it('failed missing secret', function(done) {
        s3mock.setFiles({});
        var secretId = "abc";
        var privateKey = nacl.sign.keyPair().secretKey;
        var url = '/caretakers/' + secretId + "/" + caretakerId;
        caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
            caretakerHelper.createExistingFiles(function() {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, privateKey, null, []);
        });
    });

});