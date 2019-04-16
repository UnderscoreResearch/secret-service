'use strict';

const supertest = require('supertest');
const test = require('unit.js');
const nacl = require('tweetnacl');
const app = require('../src/app.js');
const common = require('../src/common.js');
const payments = require('../src/payments.js');
const paymentmock = require('./paymentmock.js');
const secretHelper = require('./secrethelper.js');

const request = supertest(app);

describe('paymentInformation', function() {
    if (!common.fullFunctionality()) {
        return;
    }

    payments.setSquare(paymentmock, "app", "location");

    var privateKey = nacl.sign.keyPair().secretKey;
    var publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);

    it('successful', function(done) {
        secretHelper.createAuth(privateKey, 'GET', '/payments/' + publicKey, function(auth) {
            secretHelper.assignAuth(request.get('/payments/' + publicKey), auth).expect(200).end(function(err, result) {
                if (err) {
                    done(err);
                }
                else {
                    test.value(result.body).is(
                        {
                            options: {
                                "USD":{"amount":1,"token":"{\"applicationId\":\"app\",\"locationId\":\"location\"}"},
                                "ETH":{"amount":0.05,"token":"0x5D8AB714685C6F30614b6814ae9e66285de68a5D"},
                                "BTC":{"amount":0.001,"token":"3382BMuNvJuzMMViccaS4NwduCmt4YYLLo"}
                            }
                        });
                    done();
                }
            });
        });
    });

    it('fail signature', function(done) {
        secretHelper.createAuth(nacl.randomBytes(64), 'GET', '/payments/' + publicKey, function(auth) {
            secretHelper.assignAuth(request.get('/payments/' + publicKey), auth).expect(403).end(function(err, result) {
                done(err);
            });
        });
    });

    it('fail no signature', function(done) {
        request.get('/payments/' + publicKey).expect(403).end(function(err, result) {
            done(err);
        });
    });
});
