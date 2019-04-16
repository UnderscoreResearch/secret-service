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

describe('getCaretaker', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));

    it('success secret key', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                        var address = Object.assign({}, caretaker.addresses[0]);
                        delete address["addressDigest"];
                        test.value(result.body).is({
                            addresses: [address],
                            publicKey: caretaker.publicKey,
                            secretPublicKey: body.publicKey
                        });
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
                secretHelper.createAuth(otherKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                        var address = Object.assign({}, caretaker.addresses[0]);
                        delete address["addressDigest"];
                        test.value(result.body).is({
                            addresses: [address],
                            publicKey: caretaker.publicKey,
                            secretPublicKey: body.publicKey
                        });
                        done(err);
                    });
                });
            }, secretId, caretakerId, otherKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('success unlock key', function(done) {
        s3mock.setFiles({});
        var otherKey = nacl.sign.keyPair().secretKey;
        var otherPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(otherKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                        var address = Object.assign({}, caretaker.addresses[0]);
                        delete address["addressDigest"];
                        test.value(result.body).is({
                            addresses: [address],
                            publicKey: caretaker.publicKey,
                            unlockPublicKey: otherPublicKey,
                            secretPublicKey: body.publicKey
                        });
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: otherPublicKey
        }, true);
    });

    it('success other unlock key', function(done) {
        s3mock.setFiles({});
        var otherKey = nacl.sign.keyPair().secretKey;
        var otherPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(otherKey).publicKey);
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(200).end(function(err, result) {
                        var address = Object.assign({}, caretaker.addresses[0]);
                        delete address["addressDigest"];
                        test.value(result.body).is({
                            addresses: [address],
                            publicKey: caretaker.publicKey,
                            unlockPublicKey: otherPublicKey,
                            secretPublicKey: body.publicKey
                        });
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", {
                unlockPublicKey: otherPublicKey
            }, true);
        }, null, null, true);
    });

    it('fail auth', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(nacl.sign.keyPair().secretKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, null, "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        var url = '/caretakers/123/' + caretakerId;
        secretHelper.createAuth(nacl.sign.keyPair().secretKey, "GET", url, function(auth) {
            secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail missing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            secretHelper.createAuth(privateKey, "GET", url, function(auth) {
                secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send().expect(404).end(function(err, result) {
                    done(err);
                });
            });
        }, null, null, true);
    });

});