const common = require("../common.js");

module.exports.handler = function (req, res)
{
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    var s3key = common.secretKey(req.params.secretId);

    common.getS3FileMetadata(s3key, function(err, data) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var secret = common.unpackSecret(data);
        common.validateOwnership(secret.publicKey, common.decodeAuth(req), function(valid) {
            if (valid) {
                common.deleteS3Files(s3key, function(err) {
                    if (err) {
                        common.log("WARN", "Failed to delete secret", err);
                        res.status(500).end();
                    } else {
                        common.deleteS3Files(common.caretakerKey(req.params.secretId, ""), function (err) {
                            if (err) {
                                common.log("WARN", "Failed to delete secret", err);
                                res.status(500).end();
                            } else {
                                res.status(200).send(common.createMessage("Secret Deleted"));
                            }
                        });
                    }
                });
            } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
    });
}