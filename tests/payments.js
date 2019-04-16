'use strict';

const supertest = require('supertest'); 
const test = require('unit.js');
const payments = require('../src/payments.js');
const common = require('../src/common.js');
const s3mock = require('./s3mock.js');
const paymentmock = require('./paymentmock.js');
const pinpointMock = require('./pinpointmock.js');

common.setS3Client(s3mock);
common.setPinpointClient(pinpointMock);
payments.setSquare(paymentmock, "app", "location");
payments.setUrlFetcher(paymentmock);

const TESTTX = "0x8DD7429B500C142AD541185A15D84DCAD8BC4BEF1C745C9323EC0362E2B6BFE1";
const ETH_ADDRESS = "0x5D8AB714685C6F30614b6814ae9e66285de68a5D";
const ETH_AMOUNT = 50000000000000000; // 0.01 ETH
const BTC_ADDRESS = "3382BMuNvJuzMMViccaS4NwduCmt4YYLLo";
const BTC_AMOUNT = 100000; // 0.001 BTC

describe('Payments', function() {
    it('success cpn', function(done) {
        common.putS3File("transactions/CPN/whatever", "Whatever", null, () => {
            payments.validatePayment("id", 'CPN', "whatever", function(err, data) {
                if (err) {
                    done(err);
                }
                common.getS3File("transactions/CPN/whatever", function (err, data) {
                    done(!err);
                })
            });
        });
    });

    it('fail missing cpn', function(done) {
        payments.validatePayment("id", 'CPN', "test", function(err, data) {
            done(!err);
        });
    });

    it('fail invalid cpn', function(done) {
        common.putS3File("transactions/CPN/!", "Whatever", null, () => {
            payments.validatePayment("id", 'CPN', "!", function(err, data) {
                done(!err);
            });
        });
    });

    it('successful usd', function(done) {
        payments.validatePayment("id", 'USD', JSON.stringify({
            "email":"test@test.test",
            "nonce":"nonce"
        }), function(err, data) {
            done(err);
        });
    });

    it('fail usd', function(done) {
        payments.validatePayment("id", 'USD', 'wrong', function(err, data) {
            done(!err);
        });
    });

    it('fail usd result not success', function(done) {
        payments.validatePayment("id", 'USD', 'placeholder', function(err, data) {
            done(!err);
        });
    });

    it('fail usd result missing success', function(done) {
        payments.validatePayment("id", 'USD', 'placeholder', function(err, data) {
            done(!err);
        });
    });

    it('success eth', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX.substr(2)) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: ETH_AMOUNT / 2,
                            addresses: [
                                ETH_ADDRESS.substr(2)
                            ]
                        },
                        {
                            value: ETH_AMOUNT / 2,
                            addresses: [
                                ETH_ADDRESS.substr(2)
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
            if (err) {
                done(err);
                return;
            }
            common.getS3File("transactions/ETH/" + TESTTX.substr(2) + ".json.gz", function(err, data) {
                if (Math.abs(JSON.parse(data.Body).timestamp - new Date().getTime()) > 500) {
                    done("Wrong timestamp in S3 file");
                } else {
                    done(err);
                }
            });
        });
    });

    it('success eth double spend', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX.substr(2)) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: ETH_AMOUNT,
                            addresses: [
                                ETH_ADDRESS.substr(2)
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX.substr(2), function(err, data) {
            if (err) {
                done(err);
                return;
            }
            payments.validatePayment("id", 'ETH', TESTTX.toLowerCase(), function(err, data) {
                if (err) {
                    done(err);
                    return;
                }
                common.getS3File("transactions/ETH/" + TESTTX.substr(2) + ".json.gz", function(err, data) {
                    if (Math.abs(JSON.parse(data.Body).timestamp - new Date().getTime()) > 500) {
                        done("Wrong timestamp in S3 file");
                    } else {
                        done(err);
                    }
                });
            });
        });
    });

    it('fail eth double spend', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: ETH_AMOUNT,
                            addresses: [
                                ETH_ADDRESS.substr(2)
                            ]
                        }
                    ]
                }));
            }
        })
        common.putS3File("transactions/ETH/" + TESTTX + ".json.gz", JSON.stringify({
            timestamp: new Date().getTime() - 61 * 1000
        }), null, function(err, data) {
            if (err) {
                done(err);
                return;
            }
            payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
                done(!err);
            });
        });
    });

    it('fail eth too low ', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: ETH_AMOUNT / 2,
                            addresses: [
                                ETH_ADDRESS
                            ]
                        },
                        {
                            value: ETH_AMOUNT / 2,
                            addresses: [
                                "other"
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail eth no output', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail eth no confidence', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    outputs: [
                        {
                            value: ETH_AMOUNT,
                            addresses: [
                                ETH_ADDRESS.substr(2)
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail eth low confidence', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/eth/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.8,
                    outputs: [
                        {
                            value: ETH_AMOUNT,
                            addresses: [
                                ETH_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'ETH', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('success btc', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX.substr(2)) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: BTC_AMOUNT / 2,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        },
                        {
                            value: BTC_AMOUNT / 2,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
            if (err) {
                done(err);
                return;
            }
            common.getS3File("transactions/BTC/" + TESTTX.substr(2) + ".json.gz", function(err, data) {
                if (Math.abs(JSON.parse(data.Body).timestamp - new Date().getTime()) > 500) {
                    done("Wrong timestamp in S3 file");
                } else {
                    done(err);
                }
            });
        });
    });

    it('success btc double spend', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX.substr(2)) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: BTC_AMOUNT,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX.substr(2), function(err, data) {
            if (err) {
                done(err);
                return;
            }
            payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
                if (err) {
                    done(err);
                    return;
                }
                common.getS3File("transactions/BTC/" + TESTTX.substr(2) + ".json.gz", function(err, data) {
                    if (Math.abs(JSON.parse(data.Body).timestamp - new Date().getTime()) > 500) {
                        done("Wrong timestamp in S3 file");
                    } else {
                        done(err);
                    }
                });
            });
        });
    });

    it('fail btc double spend', function(done) {
        s3mock.setFiles({});

        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: BTC_AMOUNT,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        common.putS3File("transactions/BTC/" + TESTTX + ".json.gz",
            JSON.stringify({
                timestamp: (new Date().getTime() - 61 * 1000)
            }), null, function(err, data) {
            if (err) {
                done(err);
                return;
            }
            payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
                done(!err);
            });
        });
    });

    it('fail btc too low ', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                    outputs: [
                        {
                            value: BTC_AMOUNT / 2,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        },
                        {
                            value: BTC_AMOUNT / 2,
                            addresses: [
                                "other"
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail btc no output', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.999,
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail btc no confidence', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    outputs: [
                        {
                            value: BTC_AMOUNT,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
            done(!err);
        });
    });

    it('fail btc low confidence', function(done) {
        payments.setUrlFetcher(function(url, callback) {
            if (url != "https://api.blockcypher.com/v1/btc/main/txs/" + TESTTX) {
                callback("Wrong URL: " + url);
            } else {
                callback(null, JSON.stringify({
                    confidence: 0.8,
                    outputs: [
                        {
                            value: BTC_AMOUNT,
                            addresses: [
                                BTC_ADDRESS
                            ]
                        }
                    ]
                }));
            }
        })
        payments.validatePayment("id", 'BTC', TESTTX, function(err, data) {
            done(!err);
        });
    });
});
