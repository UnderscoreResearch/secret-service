const escapeHtml = require('escape-html')
const Mustache = require('mustache');
const fs = require('fs');

const common = require("./common.js");

const SES_NO_TRACK = "ses:no-trac ";

var templates = {};

function fetchTemplate(file) {
    var template = templates[file];
    if (!template) {
        template = fs.readFileSync("emailtemplates/" + file).toString();
        Mustache.parse(template);

        if (file.endsWith("html") && file !== "header.html" && file !== "footer.html") {
            template = fetchTemplate("header.html") + template + fetchTemplate("footer.html");
        }
        templates[file] = template;
    }
    return template;
}

function baseUrl() {
    if (process.env.BASE_URL) {
        return process.env.BASE_URL;
    }
    return "https://yoursharedsecret.com/";
}

function createSubject(type, title) {
    var ret = "Your Shared Secret " + type;

    if (title) {
        ret += ": " + title;
    }

    return ret;
}

function inviteMessageConfiguration(title, message, address, secretId, caretakerId, publicKey) {
    var htmlMessage = escapeHtml(message).replace(/\r?\n/g,"<br/>");
    var url = baseUrl() +
        "#s=" + secretId +
        "/c=" + caretakerId +
        "/a=" + common.encodeBin(address) +
        "/u=" + publicKey;
    if (title) {
        url += "/t=" + common.encodeBin(title)
}

    var html = Mustache.render(fetchTemplate("invite.html"), {
        title: title,
        message: htmlMessage,
        url: url,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });
    var text = Mustache.render(fetchTemplate("invite.txt"), {
        title: title,
        message: message,
        url: url,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });;

    var subject = createSubject("Invite", title);

    return {
        EmailMessage: {
            SimpleEmail: {
                HtmlPart: {
                    Data: html,
                    Charset: "UTF-8"
                },
                Subject: {
                    Data: subject,
                    Charset: "UTF-8"
                },
                TextPart: {
                    Data: text,
                    Charset: "UTF-8"
                }
            }
        }
    };
}

function unlockMessageConfiguration(title, message) {
    var htmlMessage = escapeHtml(message).replace(/\r?\n/g,"<br/>");

    var html = Mustache.render(fetchTemplate("unlock.html"), {
        title: title,
        message: htmlMessage,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });
    var text = Mustache.render(fetchTemplate("unlock.txt"), {
        title: title,
        message: message,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });;


    var subject = createSubject("Unlock Request", title);

    return {
        EmailMessage: {
            SimpleEmail: {
                HtmlPart: {
                    Data: html,
                    Charset: "UTF-8"
                },
                Subject: {
                    Data: subject,
                    Charset: "UTF-8"
                },
                TextPart: {
                    Data: text,
                    Charset: "UTF-8"
                }
            }
        }
    };
}

function shareMessageConfiguration(title, message) {
    var htmlMessage = escapeHtml(message).replace(/\r?\n/g,"<br/>");

    var html = Mustache.render(fetchTemplate("share.html"), {
        title: title,
        message: htmlMessage,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });
    var text = Mustache.render(fetchTemplate("share.txt"), {
        title: title,
        message: message,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });;


    var subject = createSubject("Unlock Request", title);

    return {
        EmailMessage: {
            SimpleEmail: {
                HtmlPart: {
                    Data: html,
                    Charset: "UTF-8"
                },
                Subject: {
                    Data: subject,
                    Charset: "UTF-8"
                },
                TextPart: {
                    Data: text,
                    Charset: "UTF-8"
                }
            }
        }
    };
}

function notifyMessageConfiguration(message) {
    var htmlMessage = escapeHtml(message).replace(/\r?\n/g,"<br/>");

    var html = Mustache.render(fetchTemplate("notify.html"), {
        message: htmlMessage,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });
    var text = Mustache.render(fetchTemplate("notify.txt"), {
        message: message,
        tags: SES_NO_TRACK,
        baseurl: baseUrl()
    });;


    var subject = createSubject("Unlock Notification");

    return {
        EmailMessage: {
            SimpleEmail: {
                HtmlPart: {
                    Data: html,
                    Charset: "UTF-8"
                },
                Subject: {
                    Data: subject,
                    Charset: "UTF-8"
                },
                TextPart: {
                    Data: text,
                    Charset: "UTF-8"
                }
            }
        }
    };
}

function receiptMessageConfiguration(amount, transaction) {
    var date = new Date().toLocaleDateString();
    var payDate = new Date(Date.now() + 366 * 24 * 60 * 60 * 1000).toLocaleDateString();

    var html = Mustache.render(fetchTemplate("receipt.html"), {
        date: date,
        payDate: payDate,
        amount: amount,
        tags: SES_NO_TRACK,
        baseurl: baseUrl(),
        transaction: transaction
    });
    var text = Mustache.render(fetchTemplate("receipt.txt"), {
        date: date,
        payDate: payDate,
        amount: amount,
        tags: SES_NO_TRACK,
        baseurl: baseUrl(),
        transaction: transaction
    });;


    var subject = createSubject("Payment Receipt");

    return {
        EmailMessage: {
            SimpleEmail: {
                HtmlPart: {
                    Data: html,
                    Charset: "UTF-8"
                },
                Subject: {
                    Data: subject,
                    Charset: "UTF-8"
                },
                TextPart: {
                    Data: text,
                    Charset: "UTF-8"
                }
            }
        }
    };
}

module.exports.send = function (sendType, address, title, message, publicKey, req, res, successCallback) {
    var messageConfig;

    switch (sendType) {
        case "INVITE":
            messageConfig = inviteMessageConfiguration(title,
                message,
                address,
                req.params.secretId,
                req.params.caretakerId,
                publicKey);
            break;
        case "UNLOCK":
            messageConfig = unlockMessageConfiguration(title, message);
            break;
        case "SHARE":
            messageConfig = shareMessageConfiguration(title, message);
            break;
        case "NOTIFY":
            messageConfig = notifyMessageConfiguration(message);
            break;
        case "RECEIPT":
            messageConfig = receiptMessageConfiguration(title, message);
            break;
    }

    var addresses = {};
    addresses[address] = {
        ChannelType: "EMAIL"
    };

    common.getPinpointClient().sendMessages({
        ApplicationId: common.getPinpointApplicationId(),
        MessageRequest: {
            Addresses: addresses,
            MessageConfiguration: messageConfig
        }
    }, function(err, data) {
        if (err) {
            common.log('ERROR', "Encountered Pinpoint error", err);
            res.status(500).send("Service I/O error");
        } else {
            if (!data.MessageResponse && !data.MessageResponse.Result || !data.MessageResponse.Result[address]) {
                common.log('ERROR', "Encountered Pinpoint error address response mismatch for address (" +
                    address + "): " + JSON.stringify(data));
                res.status(500).send("Service I/O error");
            } else if (data.MessageResponse.Result[address].DeliveryStatus !== 'SUCCESSFUL') {
                common.log('ERROR', "Encountered Pinpoint error: " + JSON.stringify(data));
                res.status(400).send(common.createMessage("Something went wrong sending message"));
            } else {
                if (successCallback)
                    successCallback();
            }
        }
    });
}
