const nacl = require('tweetnacl');
const common = require("../common.js");
const caretakers = require("../caretakers.js");

function s3key(req) {
    return common.caretakerKey(req.params.secretId, req.params.caretakerId);
}

function saveCaretaker(req, res, data) {
    common.putS3File(s3key(req), JSON.stringify(data), null, function (err, data) {
        if (err) {
            common.log("ERROR", "Failed to write caretaker to S3", err);
            res.status(500).send("Service I/O error");
        } else {
            res.send(common.createMessage("Caretaker Updated"));
        }
    });
}

function validateUnlock(req, res, secret, data) {
    if (req.body.unlockData) {
        if (req.body.unlockPublicKey !== secret.unlockPublicKey) {
            res.status(400).send(common.createMessage("Wrong unlock public key used"));
            return;
        }

        if (!common.validateEncryption(req.body.unlockData, data.publicKey)) {
            res.status(400).send(common.createMessage("Invalid unlockData field"));
        } else {
            data.unlockData = req.body.unlockData;
            data.unlockPublicKey = req.body.unlockPublicKey;

            saveCaretaker(req, res, data);
        } 
    } else {
        if (req.body.unlockPublicKey || req.body.unlockSignature) {
            res.status(400).send(common.createMessage("Unlock fields without unlockData"));
            return;
        }
        
        saveCaretaker(req, res, data);
    }
}

function validateCaretakerData(req, res, secret, data) {
    if (req.body.caretakerData) {
        if (!data.publicKey) {
            res.status(400).send(common.createMessage("Can't set caretakerData without a publicKey"));
            return;
        }
        if (!common.validateEncryption(common.decodeBin(req.body.caretakerData), data.publicKey)) {
            res.status(400).send(common.createMessage("Invalid caretakerData field"));
            return;
        }
        data.caretakerData= req.body.caretakerData;
    }
    validateUnlock(req, res, secret, data);
}

function validateData(req, res, secret, data) {
    if (req.body.data) {
        if (!common.validateEncryption(common.decodeBin(req.body.data), secret.publicKey)) {
            res.status(400).send(common.createMessage("Invalid data field"));
            return;
        }
        data.data = req.body.data;
    }
    validateCaretakerData(req, res, secret, data);
}

function validateSignature(req, res, secret, data) {
    if (!data.publicKey) {
        if (req.body.publicKey) {
            data.publicKey = req.body.publicKey;
        }
    } else if (data.publicKey && req.body.publicKey && data.publicKey !== req.body.publicKey) {
        res.status(404).send(common.notFoundMessage());
        return;
    }
    
    common.validateOwnership([secret.publicKey, data.publicKey], common.decodeAuth(req), function(valid) {
        if (valid) {
            if (req.body.addresses) {
                var addressPublicKey = data.publicKey;
                if (!addressPublicKey) {
                    addressPublicKey = secret.publicKey;
                }
                
                caretakers.validateAddresses(addressPublicKey, req.body.addresses, function(err) {
                    if (err) {
                        res.status(400).send(err);
                        return;
                    }

                    if (req.body.addressKeyDigest) {
                        data.addressKeyDigest = req.body.addressKeyDigest;
                    }
                    
                    data.addresses = req.body.addresses;
                    
                    validateData(req, res, secret, data);
                });
            } else {
                validateData(req, res, secret, data);
            }
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
    
    if (req.body.data && req.body.data.length > 2000) {
        res.status(400).send(common.createMessage("data field more than 2000 bytes."));
        return;
    }
    
    if (req.body.unlockData && req.body.unlockData.length > 2000) {
        res.status(400).send(common.createMessage("unlockData field more than 2000 bytes."));
        return;
    }

    if (req.body.secretData && req.body.secretData.length > 1000) {
        res.status(400).send(common.createMessage("secretData field too long"));
        return;
    }

    if (req.body.caretakerData && req.body.caretakerData.length > 1000) {
        res.status(400).send(common.createMessage("caretakerData field too long"));
        return;
    }

    if (req.body.addressKeyDigest && !common.decodeBin(req.body.addressKeyDigest, 64)) {
        res.status(400).send(common.createMessage("addressKeyDigest invalid"));
        return;
    }

    common.getS3File(s3key(req), function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var data = JSON.parse(data.Body);
        common.getS3FileMetadata(common.secretKey(req.params.secretId), function(err, secretData) {
            if (err) {
                common.handleS3Error(res, err);
                return;
            }
            var secret = common.unpackSecret(secretData);

            if (req.body.secretData) {
                if (!common.validateEncryption(req.body.secretData, secret.publicKey)) {
                    res.status(400).send(common.createMessage("Invalid secretData field"));
                    return;
                }
                
                data.secretData = req.body.secretData;
            }
            validateSignature(req, res, secret, data);
        });
    });
}