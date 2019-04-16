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

common.setS3Client(s3mock);
common.setPinpointClient(pinpointMock);
common.setPinpointApplicationId("appId");

const request = supertest(app);

describe('send', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    var caretakerId = common.encodeBin(nacl.randomBytes(16));
    var caretakerPrivateKey = nacl.sign.keyPair().secretKey;
    var unlockPrivateKey = nacl.sign.keyPair().secretKey;
    var unlockPublicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(unlockPrivateKey).publicKey);
    
    it('success invite', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });
    
    it('success invite no title', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        message: "Message"
                    }).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });
    
    it('success invite no message', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title"
                    }).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });
    
    it('success unlock', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(unlockPrivateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "UNLOCK",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(200).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail invite unlockPrivateKey', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(unlockPrivateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail wrong address', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "other@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail invite caretakerPrivateKey', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerPrivateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail unlock unlockPrivateKey', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "UNLOCK",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail unlock caretakerPrivateKey', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(caretakerPrivateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "UNLOCK",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(404).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail no secret', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        var url = "/caretakers/abc/def/send";
        secretHelper.createAuth(caretakerPrivateKey, "POST", url, function(auth) {
            secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                sendType: "UNLOCK",
                address: "test@example.com",
                title: "Title",
                message: "Message"
            }).expect(404).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail no caretaker', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/abc/send";
            secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                    sendType: "UNLOCK",
                    address: "test@example.com",
                    title: "Title",
                    message: "Message"
                }).expect(404).end(function(err, result) {
                    done(err);
                });
            });
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail missing address', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        title: "Title",
                        message: "Message"
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail missing sendType', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail invalid sendType', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "OTHER",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });
        
    it('fail invalid response 1', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        pinpointMock.setResult([ null, {}])
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(500).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail invalid response 2', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        pinpointMock.setResult([ null, { Result: {} }])
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(500).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail invalid response 3', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        pinpointMock.setResult([ null, { MessageResponse: { Result: { "test@example.com": { DeliveryStatus: "PERMANENT_FAILURE"}} }}]);
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(400).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

    it('fail failed pinpoint call', function(done) {
        s3mock.setFiles({});
        pinpointMock.clearMesages();
        pinpointMock.setResult([ "Doh", { Result: { "test@example.com": { DeliveryStatus: "SUCCESSFUL"}} }])
        secretHelper.createExistingFiles(function(body, privateKey, secretId) {
            var url = '/caretakers/' + secretId + "/" + caretakerId + "/send";
            caretakerHelper.createExistingFiles(function(caretaker) {
                secretHelper.createAuth(privateKey, "POST", url, function(auth) {
                    secretHelper.assignAuth(request.post(url), auth).set('Content-Type', 'application/json').send({
                        sendType: "INVITE",
                        address: "test@example.com",
                        title: "Title",
                        message: "Message"
                    }).expect(500).end(function(err, result) {
                        done(err);
                    });
                });
            }, secretId, caretakerId, caretakerPrivateKey, nacl.randomBytes(32), "test@example.com", null, true);
        }, null, {
            unlockPublicKey: unlockPublicKey
        }, true);
    });

});