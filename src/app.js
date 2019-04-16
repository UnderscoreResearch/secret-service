const express = require('express');
const bodyParser = require("body-parser");
const fs = require('fs');

const common = require("./common.js");
const swagger = require("../swagger.json");

const createSecret = require('./handlers/createsecret.js');
const updateSecret = require('./handlers/updatesecret.js');
const deleteSecret = require('./handlers/deletesecret.js');
const getSecret = require('./handlers/getsecret.js');
const unlockSecret = require('./handlers/unlocksecret.js');
const shareSecret = require('./handlers/sharesecret.js');

const checkCaretaker = require('./handlers/checkcaretaker.js');
const createCaretaker = require('./handlers/createcaretaker.js');
const deleteCaretaker = require('./handlers/deletecaretaker.js');
const updateCaretaker = require('./handlers/updatecaretaker.js');
const getCaretaker = require('./handlers/getcaretaker.js');
const getCaretakers = require('./handlers/getcaretakers.js');
const send = require('./handlers/send.js');

const paymentInformation = require('./handlers/paymentinformation.js');

var app = express();

const customDomainAdaptorMiddleware = (req,res,next)=>{
    if (!! req.headers['x-apigateway-event']){
	    const event = JSON.parse(decodeURIComponent(req.headers['x-apigateway-event']));
	    const params = event.pathParameters||{};
   
	    let interpolated_resource = Object.keys(params)
	    	.reduce((acc, k)=>acc.replace('{'+k+'}', params[k]), event.resource)

	    if ((!! event.path && !! interpolated_resource) && event.path != interpolated_resource){
		    req.url = req.originalUrl = interpolated_resource;
		    common.log("INFO", `Processing request ${event.path} for ${interpolated_resource}`);
	    } else {
            common.log("INFO", `Processing request for ${req.path}`);
	    }
    }
    next()
}

app.use(customDomainAdaptorMiddleware);

app.use(bodyParser.json({limit: '2mb'}));

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    next();
});

app.route('/')
    .get(function(req, res) {
        function filterSwagger(obj) {
            for (var key in obj) {
                if (key.startsWith("x-amazon-apigateway")) {
                    delete obj[key]
                } else {
                    var val = obj[key];
                    if (typeof val === 'object' && val !== null) {
                        filterSwagger(val);
                    }
                }
            }
        }

        var rawdata = fs.readFileSync('swagger.json');  
        var swagger = JSON.parse(rawdata);  
        swagger.info.title = swagger.info.title["Fn::Sub"].replace(" (${Stage})", "");
        
        filterSwagger(swagger);

        res.send(swagger);
    });
    
app.route('/servicetime')
    .get(function (req, res) {
        res.send({
            serviceTime: Date.now()
            });
    });

app.route('/caretakers/:secretId/:caretakerId/send')
    .post(send.handler);

if (common.fullFunctionality()) {
    app.route('/secrets')
        .post(createSecret.handler);
    
    app.route('/secrets/:secretId')
        .put(updateSecret.handler)
        .get(getSecret.handler)
        .delete(deleteSecret.handler);
    
    app.route('/secrets/:secretId/:caretakerId/unlock')
        .post(unlockSecret.handler);

    app.route('/secrets/:secretId/:caretakerId/share')
        .post(shareSecret.handler);
    
    app.route('/caretakers/:secretId')
        .get(getCaretakers.handler);
    
    app.route('/caretakers/:secretId/:caretakerId')
        .head(checkCaretaker.handler)
        .post(createCaretaker.handler)
        .put(updateCaretaker.handler)
        .delete(deleteCaretaker.handler)
        .get(getCaretaker.handler);
    
    app.route('/payments/:publicKey')
        .get(paymentInformation.handler);
}

// Export your Express configuration so that it can be consumed by the Lambda handler
module.exports = app
