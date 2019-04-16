const common = require("../common.js");
const caretakers = require("../caretakers.js");

module.exports.handler = function (req, res)
{
    if (!req.params.secretId) {
        res.status(400).send(common.createMessage("Missing secretId"));
        return;
    }
    var s3key = common.secretKey(req.params.secretId);
    common.getS3FileMetadata(s3key, function(err, secretData) {
        if (err) {
            common.handleS3Error(res, err);
            return;
        }
        var secret = common.unpackSecret(secretData);
        
        common.validateOwnership([secret.publicKey, secret.unlockPublicKey], common.decodeAuth(req), function(valid) {
            if (valid) {
                common.listS3Children(common.caretakerKey(req.params.secretId, ""), function(err, caretakerFiles) {
                   if (err) {
                       common.log("ERROR", "Failed to list caretakers", err);
                        res.status(500).send("Service I/O error");
                       return;
                   }
                   
                   if (caretakerFiles && caretakerFiles.length > 0) {
                       var files = caretakerFiles.length;
                       var combinedError;
                       var caretakerMap = {};

                       for (var i = 0; i < caretakerFiles.length; i++) {
                           const caretakerId = caretakerFiles[i];
                           common.getS3File(common.caretakerKey(req.params.secretId, caretakerId), function(err, data) {
                               if (err) {
                                   if (!combinedError) {
                                       combinedError = err;
                                   }
                               } else {
                                   data = JSON.parse(data.Body);
                                   caretakers.preparedResponseCaretaker(data, secret);
                                   caretakerMap[caretakerId] = data;
                               }
                               files--;
                               if (!files) {
                                   if (combinedError) {
                                       common.handleS3Error(res, combinedError);
                                   } else {
                                       res.send({
                                           caretakers: caretakerMap
                                       });
                                   }
                               }
                           });
                       }
                   } else {
                       res.send({
                           caretakers: {}
                       });
                   }
                });
            } else {
                res.status(404).send(common.notFoundMessage());
            }
        });
    });
}