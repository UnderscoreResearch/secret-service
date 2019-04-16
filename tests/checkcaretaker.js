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

describe('checkCaretaker', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));

    it('successful not accepted', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        } else {
                            request.head('/caretakers/' + secretId + "/" + caretakerId + "?secretPublicKey=" + body.publicKey).send().expect(200).end(function(err, result) {
                                done(err);
                            });
                        }
                    });
                });
            });
        }, null, null, true);
    });

    it('successful accepted', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                request.head('/caretakers/' + secretId + "/" + caretakerId + "?secretPublicKey=" + body.publicKey).send().expect(202).end(function(err, result) {
                    done(err);
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing secret', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                request.head('/caretakers/a/' + caretakerId + "?secretPublicKey=" + body.publicKey).send().expect(404).end(function(err, result) {
                    done(err);
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                request.head('/caretakers/' + secretId + "/b?secretPublicKey=" + body.publicKey).send().expect(404).end(function(err, result) {
                    done(err);
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail wrong publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                request.head('/caretakers/' + secretId + "/" + caretakerId + "?secretPublicKey=a").send().expect(404).end(function(err, result) {
                    done(err);
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

    it('fail missing publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                request.head('/caretakers/' + secretId + "/" + caretakerId).send().expect(400).end(function(err, result) {
                    done(err);
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, null, true);
    });

});