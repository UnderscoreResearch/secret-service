'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const app = require('../src/app.js');
const nacl = require('tweetnacl');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const caretakerHelper = require('./caretakerhelper.js');

common.setS3Client(s3mock);

const request = supertest(app);

function generateData(size) {
    var ret = "";
    for (var i = 0; i < size; i++) {
        ret += "1";
    }
    return ret;
}

describe('updateCaretaker', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));
    var otherKey = nacl.sign.keyPair().secretKey;
    var otherPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);

    var unlockKey = nacl.sign.keyPair().secretKey;
    var unlockPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(unlockKey).publicKey);

    it('success secret key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({}).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success caretaker key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var otherKey = nacl.sign.keyPair().secretKey;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({}).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success same publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        publicKey: otherPublicKey
                    }).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success set publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        publicKey: otherPublicKey
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                var body = JSON.parse(data.Body);
                                test.value(body).hasProperty("publicKey", otherPublicKey);
                                done(err);
                            });
                        }
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com");
        }, null, null, true);
    });

    it('success set address unassigned', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    caretakerHelper.createCorrectAddress(privateKey, null, "other@example.com", function(addr) {
                        secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                            addresses: [addr]
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            else {
                                common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                    var body = JSON.parse(data.Body);
                                    test.value(secretHelper.decodeEncrypted(body.addresses[0].address, publicKey).toString()).is("other@example.com");
                                    done(err);
                                });
                            }
                        });
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com");
        }, null, null, true);
    });

    it('success set address assigned', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var digest = common.encodeBin(nacl.hash(nacl.randomBytes(32)));
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    caretakerHelper.createCorrectAddress(otherKey, null, "other@example.com", function(addr) {
                        secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                            addresses: [addr],
                            addressKeyDigest: digest
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            else {
                                common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                    var body = JSON.parse(data.Body);
                                    test.value(secretHelper.decodeEncrypted(body.addresses[0].address, otherPublicKey).toString()).is("other@example.com");
                                    test.value(body.addressKeyDigest).is(digest);
                                    done(err);
                                });
                            }
                        });
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('invalid set addressKeyDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var digest = common.encodeBin(nacl.randomBytes(32));
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    caretakerHelper.createCorrectAddress(otherKey, null, "other@example.com", function(addr) {
                        secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                            addresses: [addr],
                            addressKeyDigest: digest
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success set data', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedSymmetric(common.encodeBin("data"), privateKey, nacl.randomBytes(32))
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send(originalData).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                var body = JSON.parse(data.Body);
                                test.value(body.data).is(originalData.data);
                                done(err);
                            });
                        }
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('successful secretData', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var secretData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin("abc"), privateKey,
                        nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        secretData: secretData
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        } else {
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                var body = JSON.parse(data.Body);
                                test.value(body.secretData).is(secretData);
                                done(err);
                            });
                        }
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('successful caretakerData', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var caretakerData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin("abc"), otherKey,
                        nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        caretakerData: caretakerData
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        } else {
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                var body = JSON.parse(data.Body);
                                test.value(body.caretakerData).is(caretakerData);
                                done(err);
                            });
                        }
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail caretakerData no publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var caretakerData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin("abc"), otherKey,
                        nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        caretakerData: caretakerData
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, false);
        }, null, null, true);
    });

    it('fail caretakerData wrong signature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var caretakerData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin("abc"), privateKey,
                        nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        caretakerData: caretakerData
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail caretakerData too long', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var caretakerData = "1";
                    for (var i = 0; i < 610; i++) {
                        caretaker += "1";
                    }

                    caretakerData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin(caretakerData), otherKey,
                        nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);

                    if (caretaker.length > 1002) {
                        done("Too long: " + caretakerData.length);
                        return;
                    }

                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        caretakerData: caretakerData
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, false);
        }, null, null, true);
    });

    it('fail secretData size', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var secretData = "1";
                    for (var i = 0; i < 610; i++) {
                        secretData += "1";
                    }
                    var secretData = secretHelper.encodeEncryptedAsymmetric(secretData, privateKey,
                        nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                    
                    if (secretData.length > 1002) {
                        done("Too long: " + secretData.length);
                    }
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        secretData: secretData,
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail wrong secretDataSignature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    var secretData = secretHelper.encodeEncryptedAsymmetric(common.decodeBin("abc"), otherKey,
                        nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        secretData: secretData
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail data too large', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric(generateData(1361), privateKey,
                    nacl.sign.keyPair().publicKey)
            };
            if (originalData.data.length > 2002) {
                done("Too long for test: " + originalData.data.length);
                return;
            }
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send(originalData).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success set unlockData', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric("Data", otherKey,
                    nacl.sign.keyPair.fromSecretKey(otherKey).publicKey)
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        unlockPublicKey: unlockPublicKey,
                        unlockData: originalData.data
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                var body = JSON.parse(data.Body);
                                test.value(body.unlockData).is(originalData.data);
                                test.value(body.unlockPublicKey).is(unlockPublicKey);
                                done(err);
                            });
                        }
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail set unlockData too large', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric(generateData(1361), otherKey, nacl.sign.keyPair().publicKey)
            };
            if (originalData.data.length > 2002) {
                done("Too long for test: " + originalData.data.length);
                return;
            }
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        unlockPublicKey: unlockPublicKey,
                        unlockData: originalData.data,
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail set unlockData no unlockPublicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric("abc", otherKey, nacl.sign.keyPair().publicKey)
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        unlockPublicKey: unlockPublicKey,
                        unlockData: originalData.data
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail set unlockData wrong unlockPublicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric("abc", otherKey, nacl.sign.keyPair().publicKey)
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        unlockPublicKey: unlockPublicKey,
                        unlockData: originalData.data
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey
        }, true);
    });

    it('fail set unlockData invalid signature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric("abc", unlockKey, nacl.sign.keyPair().publicKey)
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        unlockPublicKey: unlockPublicKey,
                        unlockData: originalData.data
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail set address assigned secret publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    caretakerHelper.createCorrectAddress(privateKey, null, "other@example.com", function(addr) {
                        secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                            addresses: [addr]
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail set data invalid signature', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            var originalData = {
                data: secretHelper.encodeEncryptedAsymmetric("abc", otherKey, nacl.sign.keyPair().publicKey)
            };
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send(originalData).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail different publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({
                        publicKey: "abc"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail unlock key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send({}).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey
        }, true);
    });

    it('fail auth', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(nacl.sign.keyPair().secretKey, "PUT", url, function(auth) {
                    secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, null, "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        var url = '/caretakers/123/' + caretakerId;
        secretHelper.createAuth(nacl.sign.keyPair().secretKey, "PUT", url, function(auth) {
            secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail missing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            secretHelper.createAuth(privateKey, "PUT", url, function(auth) {
                secretHelper.assignAuth(request.put(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                    done(err);
                });
            });
        }, null, null, true);
    });

});