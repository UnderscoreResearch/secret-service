const nacl = require('tweetnacl');
const common = require("../common.js");
const payments = require("../payments.js");

function updateSecret(req, res, secret, publicKey, newData) {
    const s3key = common.secretKey(req.params.secretId);

    if (!common.validateEncryption(newData, publicKey)) {
        res.status(404).send(common.notFoundMessage())
    } else {
        if (req.body.dataKeyDigest) {
            if (secret.dataKeyDigest && req.body.dataKeyDigest != secret.dataKeyDigest) {
                res.status(400).send("Can not change dataKeyDigest aftter set");
                return;
            }
            secret.dataKeyDigest = req.body.dataKeyDigest;
        }

        if (req.body.publishData) {
            secret.publishData = req.body.publishData;
        }
        delete secret["unlockPublicKey"];
        delete secret["unlockTimestamp"];
        common.putS3File(s3key, newData, common.packSecret(secret), function (err, data) {
            if (err) {
                common.log("ERROR", "Failed to update secret to S3", err);
                res.status(500).send("Service I/O error");
            } else {
                res.send(common.createMessage("Secret Updated"));
            }
        });
    }
}

function updatePublishData(req, res, secret, newData) {
    const publicKey = common.decodeBin(secret.publicKey);

    if (req.body.publishData && !common.validateEncryption(req.body.publishData, publicKey)) {
        res.status(400).send(common.createMessage("Invalid publishData field"));
    } else {
        updateSecret(req, res, secret, publicKey, newData);
    }
}

module.exports.handler = function (req, res)
{
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    var secretId = common.decodeBin(req.params.secretId, 16);
    if (!secretId) {
        res.status(404).send(common.createMessage("Missing secret"));
        return;
    }
    if (req.body.dataKeyDigest) {
        if (!common.decodeBin(req.body.dataKeyDigest, 64)) {
            res.status(400).send(common.createMessage("Malformed dataKeyDigest field"));
            return;
        }
    }

    if (!req.body.data) {
        res.status(400).send(common.createMessage("Missing data"));
        return;
    }

    const newData = common.decodeBin(req.body.data);
    if (newData.length > 1000000) {
        res.status(400).send(common.createMessage("Data too big"));
        return;
    }

    if (req.body.publishData) {
        if (req.body.publishData.length > 1000) {
            res.status(400).send(common.createMessage("publishData field too long"));
            return;
        }
    }

    if ((req.body.paymentType && !req.body.paymentToken) || (!req.body.paymentType && req.body.paymentToken)) {
        res.status(400).send(common.createMessage("Both paymentType and paymentToken must be specified if one is specified"));
        return;
    }

    const s3key = common.secretKey(req.params.secretId);

    common.getS3FileMetadata(s3key, function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        
        var secret = common.unpackSecret(data);

        common.validateOwnership(secret.publicKey, common.decodeAuth(req), function(valid) {
            if (valid) {
                if (req.body.paymentType) {
                    payments.validatePayment(req.params.secretId, req.body.paymentType, req.body.paymentToken, function(err, paymentData) {
                        if (err) {
                            common.log("WARN", err);
                            res.status(400).send(common.createMessage("Invalid payment information"));
                            return;
                        }

                        secret.payDate = payments.payDate(secret.payDate);
                        
                        updatePublishData(req, res, secret, newData);
                    });
                } else {
                    updatePublishData(req, res, secret, newData);
                }
            } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
   });
}