'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const s3mock = require('./s3mock.js');
const common = require('../src/common.js');
const secretHelper = require('./secrethelper.js');
const payments = require('../src/payments.js');
const paymentmock = require('./paymentmock.js');

payments.setSquare(paymentmock, "app", "location");
common.setS3Client(s3mock);

const request = supertest(app);

function createUpdatableSecret(callback, data, extraFields, noDataKey) {
    secretHelper.createExistingFiles(function(body, privateKey, secretId) {
        delete body["publicKey"];
        if (!data) {
            data = "Another Secret";
        }

        body.data = secretHelper.encodeEncryptedAsymmetric(data, privateKey,
            nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
        callback(body, privateKey, secretId);
    }, null, extraFields, noDataKey);
}

describe('updateSecret', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    it('successful same dataKeyDigest', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            var metadata = common.unpackSecret(data);
                            test.value(Buffer.from(secretHelper.decodeEncrypted(data.Body, publicKey, privateKey)).toString('utf8')).is("Another Secret");
                            test.value(metadata).hasNotProperty("unlockpublickey");
                            done(err);
                        });
                    }
                });
            });
        }, null, { unlockPublicKey: "unlocking" });
    });

    it('successful no dataKeyDigest', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            test.value(Buffer.from(secretHelper.decodeEncrypted(data.Body, publicKey, privateKey)).toString('utf8')).is("Another Secret");
                            done(err);
                        });
                    }
                });
            });
        }, null, {}, true);
    });

    it('successful no dataKeyDigest in update', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            delete body["dataKeyDigest"];
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;

            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            test.value(Buffer.from(secretHelper.decodeEncrypted(data.Body, publicKey, privateKey)).toString('utf8')).is("Another Secret");
                            done(err);
                        });
                    }
                });
            });
        }, null, {});
    });

    it('successful updatePayment', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            delete body["dataKeyDigest"];
            body.paymentType = 'USD';
            body.paymentToken = JSON.stringify({
                "email":"test@test.test",
                "nonce":"nonce"
            });
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;

            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            if (common.unpackSecret(data).payDate < 365 * 2 * 24 * 60 * 60 * 1000 + Date.now()) {
                                done ("Didn't update pay date");
                            } else {
                                done(err);
                            }
                        });
                    }
                });
            });
        }, null, {});
    });

    it('successful set dataKeyDigest', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            body["dataKeyDigest"] = common.encodeBin(nacl.hash(nacl.randomBytes(32)));
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;

            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            test.value(Buffer.from(secretHelper.decodeEncrypted(data.Body, publicKey, privateKey)).toString('utf8')).is("Another Secret");
                            done(err);
                        });
                    }
                });
            });
        }, null, {}, true);
    });

    it('successful publishData', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                body.publishData = secretHelper.encodeEncryptedAsymmetric("abc", privateKey,
                    nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);

                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        common.getS3File(common.secretKey(secretId), function(err, data) {
                            test.value(Buffer.from(secretHelper.decodeEncrypted(data.Body, publicKey, privateKey)).toString('utf8')).is("Another Secret");
                            test.value(Buffer.from(secretHelper.decodeEncrypted(common.unpackSecret(data).publishData, publicKey, privateKey)).toString('utf8')).is("abc");
                            done(err);
                        });
                    }
                });
            });
        }, null, {}, true);
    });

    it('fail wrong updatePayment', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            delete body["dataKeyDigest"];
            body.paymentType = 'CPN';
            body.paymentToken = JSON.stringify({
                "email":"test@test.test",
                "id":"testtoken"
            });
            var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;

            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, null, {});
    });

    it('fail publishData size', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                var publishData = "1";
                for (var i = 0; i < 610; i++) {
                    publishData += "1";
                }
                body.publishData = secretHelper.encodeEncryptedAsymmetric(publishData, privateKey,
                    nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                
                if (body.publishData.length > 1002) {
                    throw new Error("Too long: " + body.publishData.length);
                }

                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, null, {}, true);
    });

    it('fail wrong publishDataSignature', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                body.publishData = secretHelper.encodeEncryptedAsymmetric("Data", nacl.sign.keyPair().secretKey,
                    nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, null, { unlockPublicKey: "unlocking" });
    });

    it('changing dataKeyDigest', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            body["dataKeyDigest"] = common.encodeBin(nacl.hash(nacl.randomBytes(32)));

            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, null, { something: "doh", unlockPublicKey: "unlocking" });
    });

    it('wrong secretId', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretHelper.createSecretId()), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        })
    });

    it('invalid signature', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            body["data"] = secretHelper.encodeEncryptedAsymmetric("Data", nacl.sign.keyPair().secretKey, nacl.sign.keyPair().publicKey);
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        })
    });

    it('missing data', function(done) {
        s3mock.setFiles({});
        createUpdatableSecret(function(body, privateKey, secretId, files) {
            delete body["data"];
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        })
    });

    it('too large data', function(done) {
        s3mock.setFiles({});
        var data = "";
        for (var i = 0; i < 1000001 - 140; i++)
            data = data + "1";;

        createUpdatableSecret(function(body, privateKey, secretId, files) {
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(400).end(function(err, result) {
                    done(err);
                });
            });
        }, data)
    });

    it('exact size data', function(done) {
        s3mock.setFiles({});
        var data = "";
        for (var i = 0; i < 1000000 - 140; i++)
            data = data + "1";

        createUpdatableSecret(function(body, privateKey, secretId, files) {
            secretHelper.createAuth(privateKey, "PUT", '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.put('/secrets/' + secretId), auth).set('Content-Type', 'application/json').send(JSON.stringify(body)).expect(200).end(function(err, result) {
                    test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                    done(err);
                });
            });
        }, data)
    });
});