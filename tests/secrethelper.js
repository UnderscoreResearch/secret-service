'use strict';

const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');
const common = require('../src/common.js');
const payments = require('../src/payments.js');

function decodeEncrypted(encoded, signatureKey, privateKey) {
    var result = common.decodeEncryptedEnvelope(encoded);
    
    if (typeof signatureKey == "string") {
        signatureKey = common.decodeBin(signatureKey);
    }
    if (typeof privateKey == "string") {
        privateKey = common.decodeBin(privateKey);
    }

    if (!nacl.sign.detached.verify(result.message, result.signature, signatureKey)) {
        return null;
    }
    
    if (result.nonce.length > 0) {
        if (result.publicKey.length > 0) {
            return nacl.box.open(result.message, 
                result.nonce, 
                result.publicKey, 
                ed2curve.convertSecretKey(privateKey));
        }
        return nacl.secretbox.open(result.message, result.nonce, privateKey);
    } else {
        return result.message;
    }
}

function encodeEncryptionEnvelope(result) {
    var ret = new Uint8Array(4 +
        result.nonce.length +
        result.publicKey.length +
        result.signature.length +
        result.message.length);

    ret[0] = 1;
    var pos = 1;

    ret[pos] = result.nonce.length;
    pos++;
    ret.set(result.nonce, pos);
    pos += result.nonce.length;

    ret[pos] = result.publicKey.length;
    pos++;
    ret.set(result.publicKey, pos);
    pos += result.publicKey.length;

    ret[pos] = result.signature.length;
    pos++;
    ret.set(result.signature, pos);
    pos += result.signature.length;

    ret.set(result.message, pos);

    return common.encodeBin(ret);
}

function encodeEncryptedSymmetric(message, signatureKey, privateKey) {
    var result;
    if (typeof message == "string") {
        message = Buffer.from(message, "utf8");
    }
    if (typeof signatureKey == "string") {
        signatureKey = common.decodeBin(signatureKey);
    }
    if (typeof privateKey == "string") {
        privateKey = common.decodeBin(privateKey);
    }


    var nonce;
    var c;
    if (privateKey) {
        nonce = nacl.randomBytes(nacl.box.nonceLength);

        c = nacl.secretbox(message, nonce, privateKey);
    } else {
        c = message;
        nonce = Buffer.from("", "utf8");
    }
    result = {
        message: c,
        nonce: nonce,
        publicKey: Buffer.from("", "utf8"),
        signature: nacl.sign.detached(c, signatureKey)
    }

    return encodeEncryptionEnvelope(result);
}

function encodeEncryptedAsymmetric(message, signatureKey, publicKey) {
    var result;
    if (typeof message == "string") {
        message = Buffer.from(message, "utf8");
    }
    if (typeof signatureKey == "string") {
        signatureKey = common.decodeBin(signatureKey);
    }
    if (typeof publicKey == "string") {
        publicKey = common.decodeBin(publicKey);
    }

    let c;
    let p;
    let nonce;
    if (publicKey) {
        nonce = nacl.randomBytes(nacl.box.nonceLength);
        let privateKey = ed2curve.convertSecretKey(nacl.sign.keyPair().secretKey);

        p = nacl.box.keyPair.fromSecretKey(privateKey).publicKey;
        privateKey = nacl.box.before(ed2curve.convertPublicKey(publicKey), privateKey);

        c = nacl.secretbox(message, nonce, privateKey);
    } else {
        c = message;
        p = nonce = Buffer.from("", "utf8");
    }
    result = {
        nonce: nonce,
        publicKey: p,
        message: c,
        signature: nacl.sign.detached(c, signatureKey)
    };

    return encodeEncryptionEnvelope(result);
}

function createCorrectSecret(callback, data, noDataKey) {
    var privateKey = nacl.sign.keyPair().secretKey;
    var publicKey = nacl.sign.keyPair.fromSecretKey(privateKey).publicKey;
    if (!data) {
        data = "The secret data";
    }
    var encryptionKey;
    var data;
    if (!noDataKey) {
        encryptionKey = nacl.randomBytes(32);
        data = encodeEncryptedSymmetric(data, privateKey, encryptionKey);
    } else {
        encryptionKey = publicKey;
        data = encodeEncryptedSymmetric(data, privateKey, publicKey);
    }
    var secret = {
        publicKey: common.encodeBin(publicKey),
        data: data,
        paymentType: 'USD',
        paymentToken: JSON.stringify({
            "email":"test@test.test",
            "nonce":"nonce"
        })
    };
    if (!noDataKey) {
        secret["dataKeyDigest"] = common.encodeBin(nacl.hash(encryptionKey));
    }

    callback(secret, privateKey);
}

function createSecretId() {
    var secretId = nacl.randomBytes(16);
    return common.encodeBin(secretId);
}

function createExistingFiles(callback, data, extraFields, noDataKey) {
    createCorrectSecret(function(body, privateKey) {
        var secretId = createSecretId();
        var savedSecret = Object.assign({}, body);
        savedSecret["version"] = "1";
        var savedData = common.decodeBin(savedSecret["data"]);
        delete savedSecret["data"];
        savedSecret["payDate"] = payments.payDate();

        if (extraFields) {
            Object.assign(savedSecret, extraFields);
            Object.assign(body, extraFields);
        }
        common.putS3File(common.secretKey(secretId), savedData, common.packSecret(savedSecret), function(err, data) {
            if (err) {
                throw err;
            }
            callback(Object.assign({}, body), privateKey, secretId);
        });
    }, data, noDataKey);
}

function createAuth(privateKey, method, url, callback, offset) {
    if (!offset) {
        offset = 0;
    }
    var timestamp;
    if (typeof offset == "string")
        timestamp = offset;
    else
        timestamp = (Date.now() + offset).toString();

    var msg = Buffer.from(method + timestamp + url, 'utf8');
    var sig = nacl.sign.detached(msg, privateKey);
    var auth = JSON.stringify({
        t: timestamp,
        s: common.encodeBin(sig),
        method: method,
        url: url
    });
    callback(common.encodeBin(auth), common.encodeBin(nacl.sign.keyPair.fromSecretKey(privateKey).publicKey));
}

function assignAuth(request, auth) {
    request.set("x-yoursharedsecret-ownership", auth);
    return request;
}

module.exports = {
    encodeEncryptedAsymmetric: encodeEncryptedAsymmetric,
    encodeEncryptedSymmetric: encodeEncryptedSymmetric,
    decodeEncrypted: decodeEncrypted,
    createCorrectSecret: createCorrectSecret,
    createSecretId: createSecretId,
    createExistingFiles: createExistingFiles,
    createAuth: createAuth,
    assignAuth: assignAuth
}