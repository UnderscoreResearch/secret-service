const aws = require('aws-sdk');
const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');

const AUTH_HEADER = "x-yoursharedsecret-ownership";
const AUTH_MILLIS_RANGE = 60 * 1000;
const BUCKET = process.env.BUCKET;

var s3;
var pinpoint;
var pinpointApplicationId;
var betaSite;

const {gzip, ungzip} = require('node-gzip')

function log(level, msg, exc) {
    if (level == "ERROR") {
        if (exc) {
            console.error(level + ":", msg, exc);
        } else {
            console.error(level + ":", msg);
        }
    } else {
        if (exc) {
            console.log(level + ":", msg, exc);
        } else {
            console.log(level + ":", msg);
        }
    }
}

function isBetaSite() {
    if (typeof betaSite === 'undefined') {
        return BUCKET && BUCKET.indexOf("dev") >= 0;
    }
    return betaSite;
}

function setBetaSite(val) {
    betaSite = val;
}

function getS3Client() {
    if (s3) {
        return s3;
    }
    s3 = new aws.S3({
        apiVersion: '2006-03-01',
        region: 'us-west-2',
        params: { Bucket: BUCKET }
    });
    return s3;
}

function getPinpointClient() {
    if (pinpoint) {
        return pinpoint;
    }
    pinpoint = new aws.Pinpoint({
        region: process.env.AWS_REGION
    });
    return pinpoint;
}

function setPinpointClient(client) {
    pinpoint = client;
}

function getPinpointApplicationId() {
    if (!pinpointApplicationId) {
        pinpointApplicationId = process.env.PINPOINT_APPLICATION_ID
    }
    return pinpointApplicationId;
}

function setPinpointApplicationId(appId) {
    pinpointApplicationId = appId;
}

function fullFunctionality() {
    return !process.env.AWS_REGION || process.env.AWS_REGION == 'us-west-2';
}

function decodeAuth(req) {
    if (typeof req == "string") {
        try {
            return JSON.parse(decodeBin(req));
        } catch(exc) {
            return null;
        }
    }
    var header = req.get(AUTH_HEADER);
    if (header) {
        var ret = decodeAuth(header);
        if (ret) {
            ret.method = req.method;
            ret.url = req.url;
        }
        return ret;
    }
    return null;
}

function validateOwnership(publicKey, auth, callback) {
    if (!auth) {
        callback(null);
        return;
    }
    
    if (!Array.isArray(publicKey)) {
        publicKey = [ publicKey ];
    }

    var timestamp = parseInt(auth.t);
    if (typeof auth.t != "string" || typeof auth.s != "string") {
        log("INFO", "Invalid format");
        callback(null);
        return;
    }

    if (!timestamp || timestamp < Date.now() - AUTH_MILLIS_RANGE || timestamp > Date.now() + AUTH_MILLIS_RANGE) {
        callback(null);
        return;
    }


    var msg = Buffer.from(auth.method + auth.t + auth.url, 'utf8');
    var s = decodeBin(auth.s);
    
    for (var i = 0; i < publicKey.length; i++) {
        if (publicKey[i] && nacl.sign.detached.verify(msg, s, decodeBin(publicKey[i]))) {
            callback(publicKey[i]);
            return;
        }
    }
    
    callback(null);
}

function unpackSecret(data) {
    if (!data.Metadata) {
        return {};
    }
    var secret = {};
    if (data.Body) {
        secret.data = encodeBin(data.Body);
    }
    secret.publicKey = data.Metadata.p;
    secret.version = data.Metadata.v;
    if (data.Metadata.d) {
        secret.dataKeyDigest = data.Metadata.d;
    }
    if (data.Metadata.c) {
        secret.payDate = parseInt(data.Metadata.c);
    }
    if (data.Metadata.u) {
        secret.unlockPublicKey = data.Metadata.u;
    }
    if (data.Metadata.t) {
        secret.unlockTimestamp = data.Metadata.t;
    }
    if (data.Metadata.p) {
        secret.publishData = data.Metadata.a;
    }

    return secret;
}

function packSecret(data) {
    var metadata = {};
    if (data.publicKey)
        metadata.p = data.publicKey;
    if (data.version)
        metadata.v = data.version;
    if (data.dataKeyDigest)
        metadata.d = data.dataKeyDigest;
    if (data.payDate)
        metadata.c = data.payDate + "";
    if (data.unlockPublicKey)
        metadata.u = data.unlockPublicKey;
    if (data.unlockTimestamp)
        metadata.t = data.unlockTimestamp;
    if (data.publishData)
        metadata.a = data.publishData;

    return metadata;
}

function setS3Client(overrideS3) {
    s3 = overrideS3;
}

function setPinpointClient(overridePinpoint) {
    pinpoint = overridePinpoint;
}

function createMessage(message) {
  return {
    "message": message
  };
}

function notFoundMessage()
{
    return createMessage("Resource not found");
}


function decodeBin(data, length) {
    if (typeof data != "string") {
        data = data.toString();
    }
    const buffer = Buffer.from(data, 'base64');
    if (length > 0 && buffer.length != length) {
        return null;
    }
    return buffer;
}

function encodeBin(data) {
    if (typeof data == "string") {
        data = Buffer.from(data, 'utf8');
    } else if (!Buffer.isBuffer(data)) {
        data = Buffer.from(data);
    }
    return data.toString('base64')
        .replace(/=+$/,"")
        .replace(/\//g,"_")
        .replace(/\+/g,'-');
}

function getS3File(file, callback) {
    getS3Client().getObject({
        "Key": file
    }, function(err, data) {
        if (err) {
            callback(err, null);
        } else {
            ungzip(data.Body).then((uncompressed) => {
                try {
                    data.Body = uncompressed;
                    callback(null, data);
                } catch (err) {
                    log('ERROR', "Failed get file callback", err);
                    callback(err, null);
                }
            }).catch((err) => {
                callback(err, null);
            });
        }
    });
}

function getS3FileMetadata(file, callback) {
    getS3Client().headObject({
        "Key": file
    }, callback);
}

function putS3File(file, data, metadata, callback) {
    gzip(data).then((compressed) => {
        getS3Client().putObject({
            "Key": file,
            "Body": compressed,
            "Metadata": metadata
        }, function (err, data) {
            try {
                callback(err, data);
            } catch (err) {
                log('ERROR', "Failed put file callback", err);
                callback(err, null);
            }
        });
    }).catch((err) => {
        callback(err, null);
    });
}

function handleS3Error(res, err) {
    if (err.code === 'AccessDenied' || err.code === 'Forbidden' || err.code === 'NoSuchKey') {
        res.status(404).send(notFoundMessage())
    } else {
        log('ERROR', "Encountered S3 error", err);
        res.status(500).send("Service I/O error");
    }
}

// 1 week of unlock grace period in prod.
const PROD_UNLOCK_QUARANTINE_PERIOD = 7 * 24 * 60 * 60 * 1000;
// 10 minutes of unlock quarantine grace period in beta.
const BETA_UNLOCK_QUARANTINE_PERIOD =  60 * 1000;

function unlockQuarantinePeriod() {
    if (isBetaSite()) {
        return BETA_UNLOCK_QUARANTINE_PERIOD;
    }
    return PROD_UNLOCK_QUARANTINE_PERIOD;
}



function deleteS3Files(root, callback) {
    getS3Client().listObjectsV2({
        "Prefix": root
    }, function(err, data) {
        if (err) {
            callback(err);
            return;
        }
        if (data.Contents && data.Contents.length > 0) {
            getS3Client().deleteObjects({
                "Delete": {
                    "Quiet": true,
                    "Objects": data.Contents.map(function (o) {
                        return {
                            "Key": o.Key
                        };
                    })
                }
            }, callback);
        } else {
            callback(null);
        }
    });
}

function listS3Files(root, callback) {
    getS3Client().listObjectsV2({
        "Prefix": root
    }, function(err, data) {
        if (err) {
            callback(err);
        } else if (data.Contents) {
            callback(null, data.Contents.map(function (o) {
                return o.Key;
                }));
        } else {
            callback(null, []);
        }
    });
}

function listS3Children(root, callback) {
    listS3Files(root, function(err, data) {
        if (err) {
            callback(err);
        } else {
            callback(null, data.map(function(f) {
                return f.substring(root.length);
            }));
        }
    });
}

function decodeEncryptedEnvelope(encoded) {
    if (typeof encoded == "string") {
        encoded = decodeBin(encoded);
    }
    
    if (encoded[0] !== 1) {
        return null;
    }
    var nonceSize = encoded[1];
    
    if (nonceSize != 0 && nonceSize != nacl.box.nonceLength) {
        return null;
    }
    
    var nonceStart = 2;
    var nonceEnd = nonceSize + nonceStart;
    var publicKeySize = encoded[nonceEnd];
    
    if (publicKeySize != 0 && publicKeySize != nacl.box.publicKeyLength) {
        return null;
    }
    
    var publicKeyStart = nonceEnd + 1;
    var publicKeyEnd = publicKeyStart + publicKeySize;
    var signatureSize = encoded[publicKeyEnd];
    
    if (signatureSize != nacl.sign.signatureLength) {
        return null;
    }
    
    var signatureStart = publicKeyEnd + 1;
    var signatureEnd = signatureSize + signatureStart;
    var messageStart = signatureEnd;

    return {
        nonce: encoded.slice(nonceStart, nonceEnd),
        publicKey: encoded.slice(publicKeyStart, publicKeyEnd),
        signature: encoded.slice(signatureStart, signatureEnd),
        message: encoded.slice(messageStart)
    };
}

function validateEncryption(encoded, signatureKey) {
    var result = decodeEncryptedEnvelope(encoded);
    
    if (!result) {
        return false;
    }

    if (typeof signatureKey == "string") {
        signatureKey = decodeBin(signatureKey);
    }

    return nacl.sign.detached.verify(result.message, result.signature, signatureKey);
}

function caretakerKey(secretId, caretakerId) {
    return "caretakers/" + secretId + "/" + caretakerId;
}

function secretKey(secretId) {
    return "secrets/" + secretId;
}

module.exports = {
    caretakerKey: caretakerKey,
    secretKey: secretKey,
    decodeAuth: decodeAuth,
    decodeEncryptedEnvelope: decodeEncryptedEnvelope,
    validateEncryption: validateEncryption,
    validateOwnership: validateOwnership,
    setS3Client: setS3Client,
    createMessage: createMessage,
    notFoundMessage: notFoundMessage,
    encodeBin: encodeBin,
    decodeBin: decodeBin,
    getS3File: getS3File,
    getS3FileMetadata: getS3FileMetadata,
    putS3File: putS3File,
    deleteS3Files: deleteS3Files,
    listS3Files: listS3Files,
    listS3Children: listS3Children,
    handleS3Error: handleS3Error,
    log: log,
    fullFunctionality: fullFunctionality,
    unpackSecret: unpackSecret,
    packSecret: packSecret,
    getPinpointClient: getPinpointClient,
    setPinpointClient: setPinpointClient,
    getPinpointApplicationId: getPinpointApplicationId,
    setPinpointApplicationId: setPinpointApplicationId,
    isBetaSite: isBetaSite,
    setBetaSite: setBetaSite,
    unlockQuarantinePeriod: unlockQuarantinePeriod
};
