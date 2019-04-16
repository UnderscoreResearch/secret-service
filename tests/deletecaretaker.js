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

describe('deleteCaretaker', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));

    it('successful existing caretaker', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                caretakerHelper.createExistingFiles(function() {
                    secretHelper.createAuth(privateKey, "DELETE", url, function(auth) {
                        secretHelper.assignAuth(request.delete(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(200).end(function(err, result) {
                            if (err) {
                                done(err);
                            }
                            else {
                                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                                common.getS3File(common.caretakerKey(secretId, caretakerId), function(err, data) {
                                    done(!err);
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
                caretakerHelper.createExistingFiles(function() {
                    secretHelper.createAuth(nacl.sign.keyPair().secretKey, "DELETE", url, function(auth) {
                        secretHelper.assignAuth(request.delete(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(404).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, caretakerId, privateKey, null, []);
            });
        }, null, null, true);
    });

    it('failed released secret', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId;
            caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
                caretakerHelper.createExistingFiles(function() {
                    secretHelper.createAuth(privateKey, "DELETE", url, function(auth) {
                        secretHelper.assignAuth(request.delete(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(400).end(function(err, result) {
                            done(err);
                        });
                    });
                }, secretId, caretakerId, privateKey, null, []);
            });
        });
    });

    it('failed missing secret', function(done) {
        s3mock.setFiles({});
        var secretId = "abc";
        var privateKey = nacl.sign.keyPair().secretKey;
        var url = '/caretakers/' + secretId + "/" + caretakerId;
        caretakerHelper.createCorrectAddress(privateKey, null, "address@example.com", function(addr) {
            caretakerHelper.createExistingFiles(function() {
                secretHelper.createAuth(privateKey, "DELETE", url, function(auth) {
                    secretHelper.assignAuth(request.delete(url), auth).set('Content-Type', 'application/json').send({ addresses: [addr] }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, privateKey, null, []);
        });
    });

});