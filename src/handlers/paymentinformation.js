const common = require("../common.js");
const payments = require("../payments.js");

module.exports.handler = function (req, res)
{
    if (!req.params.publicKey) {
        res.status(400).send(common.createMessage("Missing publicKey"));
        return;
    }
    
    const publicKey = common.decodeBin(req.params.publicKey, 32);
    if (!publicKey) {
        res.status(400).send(common.createMessage("Invalid publicKey"));
        return;
    }

    common.validateOwnership(req.params.publicKey, common.decodeAuth(req), function(valid) {
        if (valid) {
            payments.paymentDefinition(function(err, data) {
                if (err) {
                    res.status(500).send(common.createMessage("Failed talking to payment processor"));
                } else {
                    res.send({
                        options: data
                    });
                }
            });
        } else {
            res.status(403).send(common.createMessage("Invalid signature"));
        }
    });
}