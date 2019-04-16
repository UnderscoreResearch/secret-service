const common = require("../common.js");

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
    
    common.getS3FileMetadata(common.secretKey(req.params.secretId), function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var secret = common.unpackSecret(data);

        common.validateOwnership(secret.publicKey, common.decodeAuth(req), function(valid) {
            if (valid) {
                if (secret.dataKeyDigest) {
                    res.status(400).send(common.createMessage("Can't delete a caretaker for published secret"));
                } else {
                    var s3key = common.caretakerKey(req.params.secretId, req.params.caretakerId);
                    common.deleteS3Files(s3key, function(err, data) {
                        if (err) {
                            common.log("WARN", "Failed to delete caretaker", err);
                            res.status(500).send("Service I/O error");
                        } else {
                            res.status(200).send(common.createMessage("Caretaker Deleted"));
                        }
                    });
                }
            } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
    });
}