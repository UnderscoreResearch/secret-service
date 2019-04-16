const nacl = require('tweetnacl');

const common = require("../common.js");

function validateAccess(keys, secret, req, res) {
    common.validateOwnership(keys, common.decodeAuth(req), function(valid) {
        if (valid) {
            if (secret.publicKey !== valid) {
                if (!req.query.dataKeyDigest) {
                    res.status(400).send(common.createMessage("Missing dataKeyDigest"));
                    return;
                }
    
                const keyDigest = common.decodeBin(req.query.dataKeyDigest, 64);
                if (!keyDigest) {
                    res.status(400).send(common.createMessage("Invalid dataKeyDigest"));
                    return;
                }
    
                if (common.encodeBin(nacl.hash(keyDigest)) !== secret.dataKeyDigest) {
                    res.status(403).send(common.createMessage("Incorrect dataKeyDigest"));
                    return;
                }
    
                delete secret["publishData"];
                if (!secret.unlockTimestamp) {
                    res.status(403).send("Not unlocked");
                    return;
                }
                if (parseInt(secret.unlockTimestamp) + common.unlockQuarantinePeriod() > new Date().getTime()) {
                    res.status(403).send("Too early");
                    return;
                }
            }
            
            delete secret["dataKeyDigest"];
            delete secret["version"];

            res.send(secret);
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
    var s3key = common.secretKey(req.params.secretId);

    common.getS3File(s3key, function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }

        var secret = common.unpackSecret(data);

        if (req.query.caretakerId) {
            common.getS3File(common.caretakerKey(req.params.secretId, req.query.caretakerId), function(err, data) {
                if (err) {
                    common.handleS3Error(res, err);
                    return;
                }

                validateAccess([JSON.parse(data.Body).publicKey], secret, req, res);
            });
        } else {
            validateAccess([secret.publicKey, secret.unlockPublicKey], secret, req, res);
        }
   });
}