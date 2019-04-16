'use strict';

const common = require('../src/common.js');
const nacl = require('tweetnacl');
const secrethelper = require("./secrethelper.js");

function createCorrectAddress(privateKey, encryptionKey, address, callback) {
    var addressDigest;
    var savedAddress;

    var addressBin = Buffer.from(address, 'UTF8');
    var addressDigest = common.encodeBin(nacl.hash(addressBin));

    if (encryptionKey) {

        callback({
            address: secrethelper.encodeEncryptedSymmetric(addressBin, privateKey, encryptionKey),
            addressType: 'EMAIL',
            addressDigest: addressDigest
        });
    }
    else {
        callback({
            address: secrethelper.encodeEncryptedSymmetric(addressBin, privateKey),
            addressType: 'EMAIL',
            addressDigest: addressDigest
        });
    }
}

function createCorrectCaretaker(callback, privateKey, encryptionKey, address, includePublicKey) {
    createCorrectAddress(privateKey, encryptionKey, address, function(addr) {
        var caretaker = {
            addresses: [addr]
        };

        if (encryptionKey) {
            caretaker.addressKeyDigest = common.encodeBin(nacl.hash(nacl.hash(encryptionKey)));
        }

        if (includePublicKey) {
            caretaker.publicKey = common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey);
        }

        callback(caretaker);
    });
}

function createExistingFiles(callback, secretId, caretakerId, privateKey, encryptionKey, address, extraFields, includePublicKey) {
    createCorrectCaretaker(function(caretaker) {
        var saved = Object.assign({}, caretaker);
        if (extraFields) {
            Object.assign(saved, extraFields);
        }
        common.putS3File(common.caretakerKey(secretId, caretakerId), JSON.stringify(saved), null, function(err, data) {
            if (err) {
                throw err;
            }
            callback(Object.assign({}, caretaker));
        });
    }, privateKey, encryptionKey, address, includePublicKey);
}

module.exports = {
    createCorrectAddress: createCorrectAddress,
    createExistingFiles: createExistingFiles
}
