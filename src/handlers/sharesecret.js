const nacl = require('tweetnacl');
const common = require("../common.js");
const sendMessage = require("../sendmessage.js");

module.exports.handler = function(req, res) {
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    if (!req.params.caretakerId) {
        res.status(400).send(common.createMessage("Missing caretakerId"));
        return;
    }
    if (!req.body.sharedDataKeys) {
        res.status(400).send(common.createMessage("Missing sharedDataKeys"));
        return;
    }

    for (const caretakerId in req.body.sharedDataKeys) {
        if (req.body.sharedDataKeys.hasOwnProperty(caretakerId)) {
            if (req.body.sharedDataKeys[caretakerId].length > 250) {
                res.status(400).send(common.createMessage("sharedDataKey value too large"));
                return;
            }
        }
    }

    common.getS3File(common.caretakerKey(req.params.secretId, req.params.caretakerId), function(err, caretakerData) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        else {
            caretakerData = JSON.parse(caretakerData.Body);
        }
        var secretId = req.params.secretId;
        common.getS3FileMetadata(common.secretKey(secretId), function(err, data) {
            if (err) {
                common.handleS3Error(res, err);
                return;
            }

            var secret = common.unpackSecret(data);

            common.validateOwnership(caretakerData.publicKey, common.decodeAuth(req), function(valid) {
                if (valid) {
                    if (secret.unlockPublicKey !== caretakerData.publicKey) {
                        res.status(403).send("Not the unlocking caretaker");
                        return;
                    }
        
                    if (secret.unlockTimestamp && parseInt(secret.unlockTimestamp) + common.unlockQuarantinePeriod() > new Date().getTime()) {
                        res.status(403).send("Too early");
                        return;
                    }
                    
                    for (const caretakerId in req.body.sharedDataKeys) {
                        if (req.body.sharedDataKeys.hasOwnProperty(caretakerId)) {
                            if (!common.validateEncryption(req.body.sharedDataKeys[caretakerId], secret.unlockPublicKey)) {
                                res.status(400).send(common.createMessage("Invalid sharedDataKey value signature"));
                                return;
                            }
                        }
                    }
                    
                    var promises = [];
                    var caretakers = {};

                    for (const caretakerId in req.body.sharedDataKeys) {
                        if (req.body.sharedDataKeys.hasOwnProperty(caretakerId)) {
                            promises.push(new Promise(function(resolve, reject) {
                                common.getS3File(common.caretakerKey(secretId, caretakerId), (err, data) => {
                                    if (err) {
                                        reject(err);
                                    }
                                    else {
                                        var shareData = JSON.parse(data.Body);
                                        if (!shareData.publicKey) {
                                            reject({
                                                code: "NoSuchKey"
                                            });
                                        } else {
                                            shareData.dataKey = req.body.sharedDataKeys[caretakerId];
                                            caretakers[caretakerId] = shareData;
                                            resolve();
                                        }
                                    }
                                });
                            }));
                        }
                    }
                    
                    if (promises.length == 0) {
                        res.status(400).send(common.createMessage("Missing caretakers to share with"));
                        return;
                    }

                    Promise.all(promises)
                        .then(() => {
                            promises = [];

                            for (const caretakerId in caretakers) {
                                if (caretakers.hasOwnProperty(caretakerId)) {
                                    promises.push(new Promise(function(resolve, reject) {
                                        common.putS3File(common.caretakerKey(secretId, caretakerId), JSON.stringify(caretakers[caretakerId]), null, function(err, data) {
                                            if (err) {
                                                reject(err);
                                            }
                                            else {
                                                resolve();
                                            }
                                        });
                                    }));
                                }
                            }

                            Promise.all(promises)
                                .then(() => {
                                    res.send(common.createMessage("Successfully shared"));
                                })
                                .catch((err) => {
                                    common.handleS3Error(res, err);
                                });
                        })
                        .catch((err) => {
                            common.handleS3Error(res, err);
                        })
                }
                else {
                    res.status(404).send(common.notFoundMessage());
                }
            });
        });
    });
}