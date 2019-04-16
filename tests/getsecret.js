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
common.setBetaSite(false);

const request = supertest(app);

describe('getSecret', function() {
    var dataKey = nacl.randomBytes(32);
    var dataKeyDigest = common.encodeBin(nacl.hash(dataKey));
    var dataKeyDoubleDigest = common.encodeBin(nacl.hash(common.decodeBin(dataKeyDigest)));
    var caretakerId = common.encodeBin(nacl.randomBytes(16));
    var caretakerKey = nacl.sign.keyPair().secretKey

    if (!common.fullFunctionality()) {
        return;
    }

    it('successful', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            secretHelper.createAuth(privateKey, 'GET', '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.get('/secrets/' + secretId), auth).expect(200).end(function(err, result) {
                    if (err) {
                        done(err);
                    }
                    else {
                        test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                        delete body["dataKeyDigest"];
                        delete body["paymentType"];
                        delete body["paymentToken"];
                        body["payDate"] = result.body.payDate;
                        test.value(result.body).is(body);
                        done();
                    }
                });
            }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('fail unlocking auth without unlock time', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest, function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest), auth).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });
    
    it('fail other caretakerKey wthout unlocking', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest + "&caretakerId=" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('successful unlocking auth after week', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            var unlockingTimestamp = (new Date().getTime() - 7 * 24 * 60 * 60 * 1000 - 1000) + "";
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest, function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest), auth).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            delete body["dataKeyDigest"];
                            delete body["paymentType"];
                            delete body["paymentToken"];
                            delete body["publishData"];
                            delete body["publishDataSignature"];
                            body["payDate"] = result.body.payDate;
                            body["unlockPublicKey"] = firstPublicKey;
                            body["unlockTimestamp"] = unlockingTimestamp;
                            test.value(result.body).is(body);
                            done();
                        }
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                unlockTimestamp: unlockingTimestamp,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('success other caretakerKey after week', function(done) {
        s3mock.setFiles({});
        var unlockingTimestamp = (new Date().getTime() - 7 * 24 * 60 * 60 * 1000 - 1000) + "";
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest + "&caretakerId=" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(200).end(function(err, result) {
                        if (err) {
                            done(err);
                        }
                        else {
                            test.value(result).hasHeader('content-type', 'application/json; charset=utf-8');
                            delete body["dataKeyDigest"];
                            delete body["paymentType"];
                            delete body["paymentToken"];
                            delete body["publishData"];
                            delete body["publishDataSignature"];
                            body["payDate"] = result.body.payDate;
                            test.value(result.body).is(body);
                            done();
                        }
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                unlockTimestamp: unlockingTimestamp,
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail other caretakerKey within week', function(done) {
        s3mock.setFiles({});
        var unlockingTimestamp = (new Date().getTime() - 7 * 24 * 60 * 60 * 1000 + 5000) + "";
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest + "&caretakerId=" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                unlockTimestamp: unlockingTimestamp,
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail other caretakerKey missing dataKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?caretakerId=" + caretakerId;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail other caretakerKey invalid dataKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?caretakerId=" + caretakerId + "&dataKeyDigest=abc";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail other caretakerKey wrong dataKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?caretakerId=" + caretakerId + "&dataKeyDigest=" + dataKeyDoubleDigest;
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                    secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail missing other caretakerKey', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/secrets/' + secretId + "?caretakerId=" + caretakerId + "&dataKeyDigest=" + dataKeyDigest;
            secretHelper.createAuth(caretakerKey, "GET", url, function(auth) {
                secretHelper.assignAuth(request.get(url), auth).set('Content-Type', 'application/json').send({}).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        }, null, {
                dataKeyDigest: dataKeyDoubleDigest
            }, true);
    });

    it('fail unlocking missing dataKeyDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId, function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId), auth).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('fail unlocking invalid dataKeyDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId + "?dataKeyDigest=abc", function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId + "?dataKeyDigest=abc"), auth).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('fail unlocking wrong dataKeyDigest', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDoubleDigest, function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDoubleDigest), auth).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('fail unlocking auth within week', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(firstBody, firstPrivateKey, firstSecretId) {
            var firstPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(firstPrivateKey).publicKey);
            var unlockingTimestamp = (new Date().getTime() - 7 * 24 * 60 * 60 * 1000 + 5000) + "";
            secretHelper.createExistingFiles(function(body, privateKey, secretId) {
                secretHelper.createAuth(firstPrivateKey, 'GET', '/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest, function(auth) {
                    secretHelper.assignAuth(request.get('/secrets/' + secretId + "?dataKeyDigest=" + dataKeyDigest), auth).expect(403).end(function(err, result) {
                        done(err);
                    });
                });
            }, null, {
                unlockPublicKey: firstPublicKey,
                unlockTimestamp: unlockingTimestamp,
                dataKeyDigest: dataKeyDoubleDigest
            });
        });
    });

    it('wrong auth', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            secretHelper.createAuth(privateKey, 'GET', '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.get('/secrets/' + secretId), "-" + auth).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        });
    });

    it('wrong id', function(done) {
        s3mock.setFiles({});
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            secretHelper.createAuth(privateKey, 'GET', '/secrets/' + secretId, function(auth) {
                secretHelper.assignAuth(request.get('/secrets/a' + secretId), auth).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        });
    });
});