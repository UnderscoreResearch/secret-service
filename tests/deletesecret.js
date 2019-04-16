'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const caretakerHelper = require('./caretakerhelper');

common.setS3Client(s3mock);

const request = supertest(app);

describe('deleteSecret', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    it('successful', function(done) {
        s3mock.setFiles({});
        var caretakerId = common.encodeBin(nacl.randomBytes(16));
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var otherKey = common.caretakerKey(secretId, "whatever");
            s3mock.getFiles()[otherKey] = {
                Key: otherKey
            };
            s3mock.getFiles()[common.secretKey("a" + secretId)] = {
                Key: common.secretKey("a" + secretId)
            };

            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "DELETE", '/secrets/' + secretId, function(auth) {
                    secretHelper.assignAuth(request.delete('/secrets/' + secretId), auth).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            var expectedFiles = {};
                            expectedFiles[common.secretKey("a" + secretId)] = {
                                Key: common.secretKey("a" + secretId)
                            };
                            test.value(s3mock.getFiles()).is(expectedFiles);
                            done();
                        }
                    });
                });
            }, secretId, caretakerId, nacl.sign.keyPair().secretKey, nacl.randomBytes(32), "test@example.com", null, true);
        });
    });

    it('wrong auth', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            secretHelper.createAuth(privateKey, "DELETE", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.delete('/secrets/' + secretId), "-" + auth).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        });
    });

    it('wrong id', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            secretHelper.createAuth(privateKey, "DELETE", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.delete('/secrets/a' + secretId), auth).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        });
    });
});