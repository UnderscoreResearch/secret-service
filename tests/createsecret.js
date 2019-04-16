'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const paymentmock = require('./paymentmock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const payments = require('../src/payments.js');

common.setS3Client(s3mock);
payments.setSquare(paymentmock, "app", "location");

const request = supertest(app);

describe('createSecret', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    it('successful', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                test.string(result.body.secretId);
                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                test.value(s3mock.getFiles()[common.secretKey(result.body.secretId)]).exists();
                done(err);
            });
        });
    });
    
    it('successful publishData', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body.publishData = secretHelper.encodeEncryptedAsymmetric("Doh!", privateKey,
                nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                test.string(result.body.secretId);
                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                test.value(s3mock.getFiles()[common.secretKey(result.body.secretId)]).exists();
                done(err);
            });
        });
    });

    it('fail publishData size', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            var publishData = "1";
            for (var i = 0; i < 611; i++) {
                publishData += "1";
            }
            body.publishData = secretHelper.encodeEncryptedAsymmetric(publishData, privateKey,
                nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                if (body.publishData.length > 1003) {
                    throw new Error("Too long: " + body.publishData.length);
                }
                done(err);
            });
        });
    });

    it('fail wrong publishDataSignature', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body.publishData = secretHelper.encodeEncryptedAsymmetric("abc", nacl.sign.keyPair().secretKey,
                nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail wrong payment', function(done) {
        s3mock.setFiles({});
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body.paymentType = 'CPN';
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        });
    });

    it('missing publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            delete body["publicKey"];
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        })
    });

    it('invalid dataKeyDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body["dataKeyDigest"] = "abc";
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        })
    });

    it('invalid publicKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body["publicKey"] = "abc";
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        })
    });

    it('invalid signature', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            body.publicKey = common.encodeBin(nacl.sign.keyPair().publicKey);
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        })
    });

    it('missing data', function(done) {
        s3mock.setFiles({});
        secretHelper.createCorrectSecret(function(body, privateKey) {
            delete body["data"];
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        })
    });

    it('too large data', function(done) {
        s3mock.setFiles({});
        var data = "";
        for (var i = 0; i < 1000001 - 108; i++)
            data = data + "1";;

        secretHelper.createCorrectSecret(function(body, privateKey) {
            if (common.decodeBin(body.data).length != 1000001) {
                throw new Error("Invalid length for test: " + common.decodeBin(body.data).length);
            }
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                done(err);
            });
        }, data)
    });

    it('exact size data', function(done) {
        s3mock.setFiles({});
        var data = "";
        for (var i = 0; i < 1000000 - 108; i++)
            data = data + "1";;

        secretHelper.createCorrectSecret(function(body, privateKey) {
            if (common.decodeBin(body.data).length != 1000000) {
                throw new Error("Invalid length for test: " + common.decodeBin(body.data).length);
            }
            request.post('/secrets').set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                test.string(result.body.secretId);
                test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                test.value(s3mock.getFiles()[common.secretKey(result.body.secretId)]).exists();
                done(err);
            });
        }, data)
    });

});
