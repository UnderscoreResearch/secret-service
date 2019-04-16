'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const caretakerHelper = require('./caretakerhelper.js');
const pinpointMock = require('./pinpointmock.js');

common.setPinpointClient(pinpointMock);
common.setS3Client(s3mock);

const request = supertest(app);

describe('unlockSecret', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var otherId = common.encodeBin(nacl.randomBytes(16));
    var otherKey = nacl.sign.keyPair().secretKey;
    var otherPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
    var otherDataKey = nacl.randomBytes(32);

    var unlockId = common.encodeBin(nacl.randomBytes(16));
    var unlockKey = nacl.sign.keyPair().secretKey;
    var unlockPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(unlockKey).publicKey);
    var unlockDataKey = nacl.randomBytes(32);

    var otherDataKeys = {};
    otherDataKeys[otherId] = common.encodeBin(nacl.hash(otherDataKey));

    it('success', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            common.getS3File(common.secretKey(secretId), function(err, data) {
                                test.value(common.unpackSecret(data).unlockPublicKey).is(unlockPublicKey);
                                test.value(common.unpackSecret(data).unlockTimestamp).exists();
                                test.value(data.Body).exists();
                                done(err);
                            });
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, null, true);
    });

    it('success notify', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            test.value(pinpointMock.getMessages()[0].MessageRequest.Addresses).hasProperty("notify@example.com");
                            common.getS3File(common.secretKey(secretId), function(err, data) {
                                test.value(common.unpackSecret(data).unlockPublicKey).is(unlockPublicKey);
                                test.value(common.unpackSecret(data).unlockTimestamp).exists();
                                test.value(data.Body).exists();
                                done(err);
                            });
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, null, "notify@example.com", null, true);
        }, null, null, true);
    });

    it('success single recipient', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        addressKeyDigests: {}
                    }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            test.value(common.unpackSecret(data).unlockPublicKey).is(unlockPublicKey);
                            test.value(common.unpackSecret(data).unlockTimestamp).exists();
                            test.value(data.Body).exists();
                            done(err);
                        });
                    });
                });
            }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
        }, null, null, true);
    });

    it('success otherUnlock timedout', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            common.getS3File(common.secretKey(secretId), function(err, data) {
                                test.value(common.unpackSecret(data).unlockPublicKey).is(unlockPublicKey);
                                test.value(common.unpackSecret(data).unlockTimestamp).exists();
                                test.value(data.Body).exists();
                                done(err);
                            });
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: (new Date().getTime() - 31 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail otherUnlock', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: new Date().getTime() + ""
        }, true);
    });

    it('fail auth secret', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: new Date().getTime()
        }, true);
    });

    it('fail auth other recipient', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(otherKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: otherDataKeys
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: new Date().getTime()
        }, true);
    });

    it('fail addressKeyDigests wrongDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var wrongDataKeys = {};
            wrongDataKeys[otherId] = common.encodeBin(nacl.hash(unlockDataKey));

            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(otherKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: wrongDataKeys
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: new Date().getTime()
        }, true);
    });

    it('fail addressKeyDigests missing', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(otherKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            addressKeyDigests: {}
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: new Date().getTime()
        }, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        var url = '/secrets/other/other/unlock';
        secretHelper.createAuth(otherKey, "POST", url, function(auth) {
            secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                addressKeyDigests: {}
            }).expect(404).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail missing recipient', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        addressKeyDigests: otherDataKeys
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing addressKeyDigests', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/unlock";
            secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({}).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, null, null, true);
    });
});