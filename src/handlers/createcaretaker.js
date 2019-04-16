const nacl = require('tweetnacl');
const common = require("../common.js");
const caretakers = require("../caretakers.js");

const MAX_RECIPIENTS = 16;

function saveCaretaker(s3key, req, res) {
    const data = {
        addresses: req.body.addresses,
        secretData: req.body.secretData
    };
    if (req.body.publicKey) {
        data.publicKey = req.body.publicKey;
    }

    common.putS3File(s3key, JSON.stringify(data), null, function (err, data) {
        if (err) {
            common.log("Failed to write to S3", err);
            res.status(500).send("Service I/O error");
        } else {
            res.send(common.createMessage("Caretaker Updated"));
        }
    });
}

function validateCaretaker(req, res, secret) {
    common.validateOwnership(secret.publicKey, common.decodeAuth(req), function(valid) {
        if (valid) {
            let publicKey = req.body.publicKey;
            if (!publicKey) {
                publicKey = secret.publicKey;
            }
            caretakers.validateAddresses(publicKey, req.body.addresses, function(err) {
                if (err) {
                    res.status(400).send(err);
                    return;
                }
                
                common.listS3Children(common.caretakerKey(req.params.secretId, ""), function(err, data) {
                    if (err) {
                        common.log("ERROR", "Failed to list caretakers", err);
                        res.status(500).send("Service I/O error");
                    } else {
                        if (data.length >= MAX_RECIPIENTS) {
                            res.status(400).send(common.createMessage("Too many caretakers"));
                            return;
                        }

                        var s3key = common.caretakerKey(req.params.secretId, req.params.caretakerId);
                        if (data.filter(t => t === req.params.caretakerId).length == 0) {
                            saveCaretaker(s3key, req, res);
                        } else {
                            common.getS3File(s3key, function(err, data) {
                                if (!err) {
                                    var data = JSON.parse(data.Body);
                                    if (data.publicKey) {
                                        res.status(400).send(common.createMessage("Can't create a caretaker that is already accepted"));
                                        return;
                                    }
                                }
                                saveCaretaker(s3key, req, res);
                            });
                        }
                    }
                });
            });
        } else {
            res.status(404).send(common.notFoundMessage());
        }
    });
}

module.exports.handler = function (req, res)
{
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    if (!req.params.caretakerId) {
        res.status(400).send(common.createMessage("Missing caretakerId"));
        return;
    }
    
    if (req.params.caretakerId.length > 30) {
        res.status(400).send(common.createMessage("CaretakerId too long"));
        return;
    }

    if (req.body.secretData) {
        if (req.body.secretData.length > 1000) {
            res.status(400).send(common.createMessage("secretData field too long"));
            return;
        }
    }
    
    var s3key = common.secretKey(req.params.secretId);

    common.getS3FileMetadata(s3key, function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var secret = common.unpackSecret(data);

        if (req.body.secretData && !common.validateEncryption(req.body.secretData, secret.publicKey)) {
            res.status(400).send(common.createMessage("secretData is invalid"));
        } else {
            validateCaretaker(req, res, secret);
        }
   });
}