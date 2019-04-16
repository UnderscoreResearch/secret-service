const nacl = require('tweetnacl');
const common = require("../common.js");
const sendMessage = require("../sendmessage.js");

const PROD_UNLOCK_TIMEOUT_PERIOD = 30 * 24 * 60 * 60 * 1000;
const DEV_UNLOCK_TIMEOUT_PERIOD = 60 * 1000;

const WRONG_ADDRESS_MESSAGE = 'Wrong dataKeyDigest';

function getUnlockTimeoutPeriod() {
    if (common.isBetaSite()) {
        return DEV_UNLOCK_TIMEOUT_PERIOD;
    } else {
        return PROD_UNLOCK_TIMEOUT_PERIOD;
    }
}

function saveUnlock(secretData, secret, req, res) {
    var s3key = common.secretKey(req.params.secretId);

    common.putS3File(s3key, secretData.Body, common.packSecret(secret), function (err, data) {
        if (err) {
            common.log("ERROR", "Failed to write to S3", err);
            res.status(500).send("Service I/O error");
        } else {
            res.send(common.createMessage("Secret Unlocked"));
        }
    });
}

function unlockSecret(notificationAddress, caretakerData, req, res) {
    var s3key = common.secretKey(req.params.secretId);

    common.getS3File(s3key, function(err, secretData) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var secret = common.unpackSecret(secretData);
        if (!secret.unlockPublicKey || secret.unlockPublicKey !== caretakerData.publicKey) {
            if (secret.unlockPublicKey) {
                if (secret.unlockTimestamp && parseInt(secret.unlockTimestamp) + getUnlockTimeoutPeriod() > new Date().getTime()) {
                    res.status(400).send("Secret is already unlocked by another caretaker");
                    return;
                }
            }
            secret.unlockPublicKey = caretakerData.publicKey;
            secret.unlockTimestamp = new Date().getTime() + "";

            if (notificationAddress) {
                sendMessage.send('UNLOCK',
                    notificationAddress,
                    null,
                    req.params.secretId,
                    secret.publicKey,
                    req, res, function() {
                    saveUnlock(secretData, secret, req, res);
                });
            } else {
                saveUnlock(secretData, secret, req, res);
            }
        } else {
            res.send(common.createMessage("Secret already unlocked"));
        }
    });
}

module.exports.handler = function (req, res) {
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    if (!req.params.caretakerId) {
        res.status(400).send(common.createMessage("Missing caretakerId"));
        return;
    }
    if (!req.body.addressKeyDigests) {
        res.status(400).send(common.createMessage("Missing addressKeyDigests"));
        return;
    }

    common.getS3File(common.caretakerKey(req.params.secretId, req.params.caretakerId), function(err, caretakerData) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        } else {
            caretakerData = JSON.parse(caretakerData.Body);
        }
        common.validateOwnership(caretakerData.publicKey, common.decodeAuth(req), function(valid) {
            if (valid) {
                var s3key = common.caretakerKey(req.params.secretId, "");
                common.listS3Children(s3key, function(err, caretakerFiles) {
                    if (err) {
                       common.log("ERROR", "Failed to list caretakers", err);
                        res.status(500).send("Service I/O error");
                       return;
                    }
                   
                    var notificationAddress = null;

                    Promise.all(caretakerFiles.map((caretakerId) => new Promise((resolve, reject) => {
                        if (caretakerId !== req.params.caretakerId) {
                            common.getS3File(s3key + caretakerId, function (err, data) {
                                if (err) {
                                    reject(err);
                                } else {
                                    data = JSON.parse(data.Body);

                                    if (data.addressKeyDigest && data.data) {
                                        var key = req.body.addressKeyDigests[caretakerId];
                                        if (key) {
                                            if (common.encodeBin(nacl.hash(common.decodeBin(key))) !== data.addressKeyDigest) {
                                                reject(new Error(WRONG_ADDRESS_MESSAGE));
                                                return;
                                            }
                                        } else {
                                            reject(new Error(WRONG_ADDRESS_MESSAGE));
                                            return;
                                        }
                                    } else {
                                        for (var j = 0; j < data.addresses.length; j++) {
                                            var addressRecord = data.addresses[j];
                                            if (addressRecord.addressType === 'EMAIL') {
                                                var addr = common.decodeEncryptedEnvelope(addressRecord.address);
                                                if (addr.nonce.length == 0) {
                                                    notificationAddress = addr.message.toString('utf8');
                                                }
                                            }
                                        }
                                    }
                                }
                                resolve();
                            });
                        } else {
                            resolve();
                        }
                    }))).then(() => {
                        unlockSecret(notificationAddress, caretakerData, req, res);
                    }).catch((err) => {
                        if (err.message == WRONG_ADDRESS_MESSAGE) {
                            res.status(400).send(common.createMessage(WRONG_ADDRESS_MESSAGE));
                            return;
                        }
                        common.handleS3Error(res, err);
                        return;
                    });
                 });
        } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
    });
}