'use strict';

var existingSends = [];
var predefinedResult;

module.exports.sendMessages = function(msg, callback) {
    existingSends.push(msg);
    var err;
    var result;
    if (predefinedResult) {
        err = predefinedResult[0];
        result = predefinedResult[1];
    } else {
        result = {
            MessageResponse: {
                Result: {}
            }
        };
        for (var address in msg.MessageRequest.Addresses) {
            result.MessageResponse.Result[address] = {
                DeliveryStatus: 'SUCCESSFUL'
            };
        }
    }
    callback(err, result);
}

module.exports.clearMesages = function() {
    existingSends = [];
    predefinedResult = null;
}

module.exports.setResult = function(result) {
    predefinedResult = result;
}

module.exports.getMessages = function() {
    return existingSends;
}