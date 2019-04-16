const SquareConnect = require('square-connect');
const https = require('https');

const common = require("./common.js");
const sendMessage = require('./sendmessage');

const ETH_ADDRESS = "0x5D8AB714685C6F30614b6814ae9e66285de68a5D";
const ETH_AMOUNT = 50000000000000000;  // 0.05 BTC
const BTC_ADDRESS = "3382BMuNvJuzMMViccaS4NwduCmt4YYLLo";
const BTC_AMOUNT = 100000; // 0.001 BTC
const BTC_AMOUNT_DISPLAY = BTC_AMOUNT / 100000000;
const ETH_AMOUNT_DISPLAY = ETH_AMOUNT / 1e18;
const USD_AMOUNT = "1.00"; // 1 USD
const DOUBLE_SPEND_PERIOD = 1000 * 60; // How long we allow to reuse a token

var squareClient;
var squareApplicationId;
var squareLocationId;

function getSquareLocationId() {
    if (!squareLocationId) {
        return process.env.SQUARE_LOCATION_ID;
    }
    return squareLocationId;
}

function getSquareApplicationId() {
    if (!squareApplicationId) {
        return process.env.SQUARE_APPLICATION_ID;
    }
    return squareApplicationId;
}

var fetchUrl = function(url, callback) {
    https.get(url, (resp) => {
        
        let data = '';
        
        // A chunk of data has been recieved.
        resp.on('data', (chunk) => {
            data += chunk;
        });
        
        // The whole response has been received. Print out the result.
        resp.on('end', () => {
            callback(null, data);
        });
    
    }).on("error", (err) => {
        callback(err);
    });
}

function setSquare(s, applicationId, locationId) {
    squareClient = s;
    squareApplicationId = applicationId;
    squareLocationId = locationId;
}

function getSquareClient() {
    if (squareClient) {
        return squareClient;
    }

    var client = SquareConnect.ApiClient.instance;
    var oauth2 = client.authentications['oauth2'];
    oauth2.accessToken = process.env.SQUARE_ACCESS_TOKEN;

    squareClient = new SquareConnect.TransactionsApi();
    return squareClient;
}

function setUrlFetcher(fetcher) {
    fetchUrl = fetcher;
}

function normalizeTransaction(str) {
    if (str.startsWith("0x")) {
        return str.substr(2).toUpperCase();
    }
    if (/[G-Zg-z]/.test(str)) {
        return str;
    }
    return str.toUpperCase();
}

function validateTransaction(secretId, type, transaction, address, amount, callback) {
    transaction = normalizeTransaction(transaction);

    fetchUrl('https://api.blockcypher.com/v1/' + type.toLowerCase() + '/main/txs/' +  transaction, function(err, data) {
        if (err) {
            callback(err);
            return;
        }
        try {
            var tx = JSON.parse(data);
            
            if (tx.confidence < 0.99) {
                callback("Too low confidence on this transaction");
                return;
            }
            
            if (!tx.outputs) {
                callback("Transaction has no outputs");
                return;
            }
        
            var left = amount;
            for (var i = 0; i < tx.outputs.length; i++) {
                var output = tx.outputs[i];
                if (output.addresses) {
                    for (var j = 0; j < output.addresses.length; j++) {
                        if (normalizeTransaction(output.addresses[j]) === normalizeTransaction(address)) {
                            left -= output.value;
                            break;
                        }
                    }
                }
            }
        
            if (left > 0) {
                callback("Insufficient amount was transfered to correct address (" + left + " missing)");
                return;
            }
            
            var key = "transactions/" + type + "/" + transaction + ".json.gz";
            
            common.getS3File(key, function(err, data) {
                if (!err) {
                    var data = JSON.parse(data.Body);
                    if (data.timestamp + DOUBLE_SPEND_PERIOD < new Date().getTime()) {
                        callback("This transaction has already been used");
                        return;
                    }
                    
                    callback(null, "Success");
                } else {
                    common.putS3File(key, JSON.stringify({
                        timestamp: Date.now(),
                        secretId: secretId
                    }), null, function(err, data) {
                        if (err) {
                            common.log("WARN", "Failed to save double spend protection for " + key + ": " + err);
                            callback(null, "Success")
                        } else {
                            callback(null, "Success");
                        }
                    });
                }
            });
        } catch (e) {
          callback(e);
        }
    });
}

function validatePayment(secretId, type, token, callback) {
    if (type == "USD") {
        try {
            var data = JSON.parse(token);

            var body = new SquareConnect.ChargeRequest();
            body.card_nonce = data.nonce;
            body.buyer_email_address = data.email;
            body.note = 'Your Shared Secret';
            body.idempotency_key = data.nonce;
            body.amount_money = {
                amount: USD_AMOUNT * 100,
                currency: 'USD'
            };

            getSquareClient().charge(getSquareLocationId(), body).then(function(response) {
                sendMessage.send('RECEIPT', data.email, USD_AMOUNT, response.transaction.id);

                var key = "transactions/" + type + "/" + response.transaction.id + ".json.gz";

                common.putS3File(key, JSON.stringify({
                    timestamp: Date.now(),
                    secretId: secretId,
                    email: data.email
                }), null, function(err, data) {
                    if (err) {
                        common.log("WARN", "Failed to save double spend protection for " + key + ": " + err);
                        callback(null, "Success")
                    } else {
                        callback(null, "Success");
                    }
                });
            }, function(error) {
                callback(error);
            });
        } catch (err) {
            callback(err);
        }
    } else if (type == "BTC") {
      validateTransaction(secretId, type, token, BTC_ADDRESS, BTC_AMOUNT, callback);
    } else if (type == "ETH") {
        validateTransaction(secretId, type, token, ETH_ADDRESS, ETH_AMOUNT, callback);
    } else if (type == 'CPN') {
        if (token.match(/[^A-Za-z0-9_-]/)) {
            callback("Invalid coupon");
        } else {
            var key = "transactions/" + type + "/" + token;
            common.getS3FileMetadata(key, function(err, data) {
                if (err) {
                    callback("Invalid coupon");
                } else {
                    common.deleteS3Files(key, function (err, data) {
                        callback(null, 'Success');
                    });
                }
            });
        }
    } else {
        callback("Invalid payment type");
    }
}

function paymentDefinition(callback) {
    callback(null, {
        USD: {
            amount: 1.0,
            token: JSON.stringify({
                applicationId: getSquareApplicationId(),
                locationId: getSquareLocationId()
            })
        },
        ETH: {
            amount: ETH_AMOUNT_DISPLAY,
            token: ETH_ADDRESS
        },
        BTC: {
            amount: BTC_AMOUNT_DISPLAY,
            token: BTC_ADDRESS
        }
    });
}

function payDate(current) {
    if (!current || current < Date.now()) {
        current = Date.now();
    }
    return current + 366 * 24 * 60 * 60 * 1000;
}

module.exports = {
    validatePayment: validatePayment,
    setSquare: setSquare,
    payDate: payDate,
    getSquareClient: getSquareClient,
    getSquareApplicationId: getSquareApplicationId,
    getSquareLocationId: getSquareLocationId,
    setUrlFetcher: setUrlFetcher,
    paymentDefinition: paymentDefinition
};