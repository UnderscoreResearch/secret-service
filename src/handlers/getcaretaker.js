const common = require("../common.js");
const caretakers = require("../caretakers.js");

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
    var s3key = common.caretakerKey(req.params.secretId, req.params.caretakerId);
    common.getS3File(s3key, function(err, data) {
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
            
            common.validateOwnership([secret.publicKey, secret.unlockPublicKey, data.publicKey], common.decodeAuth(req), function(valid) {
                if (valid) {
                    caretakers.preparedResponseCaretaker(data, secret);
                    res.send(data);
                } else {
                    res.status(404).send(common.notFoundMessage());
                }
            });
        });
    });
}