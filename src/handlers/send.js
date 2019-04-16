const nacl = require('tweetnacl');
const common = require("../common.js");

const sendMessage = require("../sendmessage.js");

function validateCaretaker(secret, req, res) {
    var s3key = common.caretakerKey(req.params.secretId, req.params.caretakerId);
    common.getS3File(s3key, function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var data = JSON.parse(data.Body);
        
        var addressDigest = common.encodeBin(nacl.hash(Buffer.from(req.body.address, 'utf8')));

        for (var i = 0; i < data.addresses.length; i++) {
            if (data.addresses[i].addressDigest === addressDigest) {
                sendMessage.send(req.body.sendType,
                    req.body.address,
                    req.body.title,
                    req.body.message,
                    secret.publicKey,
                    req, res, function() {
                    res.status(200).send(common.createMessage("Message Sent"));
                });
                return;
            }
        }
        
        res.status(404).send(common.notFoundMessage());
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
    
    if (req.body.sendType != 'INVITE' && req.body.sendType != 'UNLOCK' && req.body.sendType != 'SHARE') {
        res.status(400).send(common.createMessage("Invalid sendType"));
        return;
    }
    
    if (!req.body.address) {
        res.status(400).send(common.createMessage("Missing address"));
        return;
    }

    var s3key = common.secretKey(req.params.secretId);
    common.getS3FileMetadata(s3key, function(err, secretData) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        
        var publicKey;
        
        var secret = common.unpackSecret(secretData);
        
        if (req.body.sendType == 'INVITE') {
            publicKey = secret.publicKey;
        } else {
            if (!secret.unlockPublicKey) {
                res.status(404).send(common.notFoundMessage());
                return;
            }
            
            publicKey = secret.unlockPublicKey;
        }

        common.validateOwnership([publicKey], common.decodeAuth(req), function(valid) {
            if (valid) {
                validateCaretaker(secret, req, res);
            } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
    });
}
