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
common.setBetaSite(false);

const request = supertest(app);

describe('shareSecret', function() {
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
    otherDataKeys[otherId] = secretHelper.encodeEncryptedAsymmetric(nacl.randomBytes(32), unlockKey, otherPublicKey);

    it('success', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: otherDataKeys
                        }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                                return;
                            }
                            common.getS3File(common.caretakerKey(secretId, otherId), function(err, data) {
                                test.value(JSON.parse(data.Body).dataKey).is(otherDataKeys[otherId]);
                                done(err);
                            });
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail too big', function(done) {
        s3mock.setFiles({});

        var tooLargeDataKeys = {};
        tooLargeDataKeys[otherId] = secretHelper.encodeEncryptedAsymmetric(nacl.randomBytes(100), unlockKey, otherPublicKey);

        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: tooLargeDataKeys
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail missing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/a" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: otherDataKeys
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail not unlocking', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: otherDataKeys
                        }).expect(403).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/a' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: otherDataKeys
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail no caretakers', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: {}
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail missing caretakers', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({}).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('fail too early', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: otherDataKeys
                        }).expect(403).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 6 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('missing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: {
                                "other": otherDataKeys[otherId]
                            }
                        }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });

    it('wrong signature', function(done) {
        s3mock.setFiles({});
   
       var wrongDataKeys = {};
        wrongDataKeys[otherId] = secretHelper.encodeEncryptedAsymmetric(nacl.randomBytes(32), otherKey, otherPublicKey);

        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "/" + unlockId + "/share";
            caretakerHelper.createExistingFiles(function(caretaker) {
                caretakerHelper.createExistingFiles(function(caretaker) {
                    secretHelper.createAuth(unlockKey, "POST", url, function(auth) {
                        secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                            sharedDataKeys: wrongDataKeys
                        }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, unlockId, unlockKey, unlockDataKey, "test@example.com", null, true);
            }, secretId, otherId, otherKey, otherDataKey, "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey,
            unlockTimestamp: (new Date().getTime() - 8 * 24 * 60 * 60 * 1000) + ""
        }, true);
    });


});