const nacl = require('tweetnacl');
const common = require("./common.js");

const MAX_ADDRESSES = 10;
const MAX_ADDRESS_LENGTH = 1000;

function validateAddresses(publicKey, addresses, callback) {
    if (addresses && addresses.length > 0) {
        if (addresses.length > MAX_ADDRESSES) {
            callback(common.createMessage("More than 10 addresses specified"));
            return;
        }
        var address = addresses[0];

        if (!address.address) {
            callback(common.createMessage("Missing address"));
            return;
        }
        if (address.address.length > MAX_ADDRESS_LENGTH) {
            callback(common.createMessage("Too long address"));
            return;
        }
        if (!address.addressType) {
            callback(common.createMessage("Missing addressType"));
            return;
        }
        if (address.addressType !== 'EMAIL' && address.addressType !== 'GCM' && address.addressType !== 'APNS' && address.addressType !== 'MAIL') {
            callback(common.createMessage("Invalid addressType"));
            return;
        }

        if (!address.addressDigest) {
            callback(common.createMessage("Missing addressDigest"));
            return;
        }

        var addressDigest = common.decodeBin(address.addressDigest, 64);
        if (!addressDigest) {
            callback(common.createMessage("Invalid addressDigest"));
            return;
        }

        if (!common.validateEncryption(address.address, publicKey)) {
            callback(common.createMessage("Invalid address signature"));
        } else {
            validateAddresses(publicKey, addresses.splice(1), callback);
        }
    } else {
        callback(null);
    }
}

function preparedResponseCaretaker(caretaker, secret) {
    if (secret.unlockPublicKey) {
        if (caretaker.unlockPublicKey) {
            if (caretaker.unlockPublicKey !== secret.unlockPublicKey) {
                delete caretaker["unlockPublicKey"];
                delete caretaker["unlockData"];
            }
        }

        caretaker.unlockPublicKey = secret.unlockPublicKey;
        if (caretaker.dataKey) {
            if (!common.validateEncryption(caretaker.dataKey, caretaker.unlockPublicKey)) {
                delete caretaker.dataKey;
            }
        }
    } else {
        delete caretaker.dataKey;
    }
    
    delete caretaker["addressKeyDigest"];

    caretaker.secretPublicKey = secret.publicKey;

    if (caretaker.addresses) {
        for (var i = 0; i < caretaker.addresses.length; i++) {
            var address = caretaker.addresses[i];
            delete address["addressDigest"];
        }
    }
}

module.exports = {
    validateAddresses: validateAddresses,
    preparedResponseCaretaker: preparedResponseCaretaker
};
