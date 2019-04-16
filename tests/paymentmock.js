'use strict';

const payments = require("../src/payments");

module.exports.charge = function (location, transaction) {
    return new Promise(function (resolve, reject) {
        if (location !== "location") {
            reject("Invalid location");
        }
        if (transaction.card_nonce !== "nonce") {
            reject("Invalid nonce");
        }
        if (transaction.buyer_email_address !== 'test@test.test') {
            reject("Invalid email");
        }
        if (transaction.idempotency_key !== "nonce") {
            reject("Invalid idempotency");
        }
        if (transaction.amount_money.amount !== 100) {
            reject("Invalid amount");
        }
        if (transaction.amount_money.currency !== 'USD') {
            reject("Invalid currency");
        }
        resolve({
            transaction: {
                id: "id"
            }
        });
    });
}
