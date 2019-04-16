'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const caretakerHelper = require('./caretakerhelper.js');

common.setS3Client(s3mock);

const request = supertest(app);

function testSuccess(secretId, secret, privateKey, unlockKey, done) {
    var url = '/caretakers/' + secretId;
    caretakerHelper.createExistingFiles(function(caretaker1) {
        caretakerHelper.createExistingFiles(function(caretaker2) {
            secretHelper.createAuth(privateKey, "GET", url, function(auth) {
                secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                    var address1 = Object.assign({}, caretaker1.addresses[0]);
                    var address2 = Object.assign({}, caretaker2.addresses[0]);
                    delete address1["addressDigest"];
                    delete address2["addressDigest"];
                    var expected = {
                        caretakers: {
                            "0": {
                                addresses: [address1],
                                publicKey: caretaker1.publicKey,
                                secretPublicKey: secret.publicKey
                            },
                            "1": {
                                addresses: [address2],
                                publicKey: caretaker2.publicKey,
                                secretPublicKey: secret.publicKey
                            }
                        }
                    };
                    if (unlockKey) {
                        Object.keys(expected.caretakers).forEach(t => expected.caretakers[t]["unlockPublicKey"] = unlockKey);
                    }
                    test.value(result.body).is(expected);
                    done(err);
                });
            });
        }, secretId, "1", nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
    }, secretId, "0", nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
}

describe('getCaretakers', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));

    it('success secret key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            testSuccess(secretId, body, privateKey, null, done)
        }, null, null, true);
    });

    it('success unlock key', function(done) {
        s3mock.setFiles({});
        var otherKey = nacl.sign.keyPair().secretKey;
        var otherPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            testSuccess(secretId, body, otherKey, otherPublicKey, done)
        }, null, {
            unlockPublicKey: otherPublicKey
        }, true);
    });

    it('success no caretakers', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId;
            secretHelper.createAuth(privateKey, "GET", url, function(auth) {
                secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                    test.value(result.body).is({ caretakers: {} });
                    done(err);
                });
            });
        }, null, null, true);
    });

    it('fail invalid key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId;
            secretHelper.createAuth(nacl.sign.keyPair().secretKey, "GET", url, function(auth) {
                secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                    done(err);
                });
            });
        }, null, null, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        var url = '/caretakers/123';
        secretHelper.createAuth(nacl.sign.keyPair().secretKey, "GET", url, function(auth) {
            secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                done(err);
            });
        });
    });

});