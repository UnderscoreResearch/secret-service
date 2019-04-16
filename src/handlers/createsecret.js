const nacl = require('tweetnacl');
const common = require("../common.js");
const payments = require("../payments.js");

function uploadSecret(req, res, publicKey, data)
{
    var secretId = common.encodeBin(nacl.randomBytes(16));
    payments.validatePayment(secretId, req.body.paymentType, req.body.paymentToken, function(err, paymentData) {
        if (err) {
            common.log("WARN", err);
            res.status(400).send(common.createMessage("Invalid payment information"));
            return;
        }

        if (!common.validateEncryption(req.body.data, req.body.publicKey)) {
            res.status(400).send(common.createMessage("Data field invalid"));
            return;
        }
        
        var metadata = {
            publicKey: req.body.publicKey,
            version: '1',
            payDate: payments.payDate()
        };
            
        if (req.body.dataKeyDigest) {
            metadata.dataKeyDigest = req.body.dataKeyDigest;
        }
        if (req.body.publishData) {
            metadata.publishData = req.body.publishData;
        }

        common.putS3File(common.secretKey(secretId), data, common.packSecret(metadata), function (err, data) {
                if (err) {
                    common.log("Failed to write secret to S3", err);
                    res.status(500).send("Service I/O error");
                } else {
                    res.send({
                        "secretId": secretId
                    });
                }
        });
    });
}

module.exports.handler = function (req, res)
{
    if (!req.body.publicKey) {
        res.status(400).send(common.createMessage("Missing publicKey"));
        return;
    }
    if (!req.body.data) {
        res.status(400).send(common.createMessage("Missing data"));
        return;
    }
    
    const publicKey = common.decodeBin(req.body.publicKey, 32);
    if (!publicKey) {
        res.status(400).send(common.createMessage("Malformed publicKey field"));
        return;
    }
    if (req.body.dataKeyDigest) {
        if (!common.decodeBin(req.body.dataKeyDigest, 64)) {
            res.status(400).send(common.createMessage("Malformed dataKeyDigest field"));
            return;
        }
    }
    const data = common.decodeBin(req.body.data);
    if (data.length > 1000000) {
        res.status(400).send(common.createMessage("Data too big"));
        return;
    }

    if (req.body.publishData) {
        if (req.body.publishData.length > 1000) {
            res.status(400).send(common.createMessage("publishData field too long"));
            return;
        }
    }

    if (req.body.publishData && !common.validateEncryption(req.body.publishData, req.body.publicKey)) {
        res.status(400).send(common.createMessage("publishData is invalid"));
    } else {
        uploadSecret(req, res, publicKey, data);
    }
}