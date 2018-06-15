'use strict';
const querystring = require('querystring');
const crypto = require('crypto');
const url = require('url');
const p = require('promises');
const c = require('consts');

console.log("Loading Application Framework function");

var dataObj = {};
var stageVariables = {};
var qs = {};

function activation() {
    if (!("params" in qs)) {
        return Promise.reject("Missing activation parameters");
    }
    let decodedParams = Buffer.from(qs.params, 'base64').toString('ascii');
    let decQs = querystring.parse(decodedParams);
    if (!("instance_id" in decQs)) {
        return Promise.reject("Missing parameters {instance_id}");
    }
    if (!("region" in decQs)) {
        return Promise.reject("Missing parameters {region}");
    }
    dataObj.instance_id = decQs.instance_id;
    dataObj.apiKey = crypto.createHash('sha256').update(decQs.instance_id).digest('hex');
    dataObj.instance_secret = crypto.createHmac(
        'sha256',
        dataObj.stageVariables.applicationSharedSecret
    ).update(dataObj.apiKey).digest('hex');
    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + dataObj.instance_secret;
    // Let's get the master secret and redirect the user to AUTH
    return p.checkExisting(dataObj).then(p.getMasterSecret).then(
        () => {
            let returnObject = {
            };
            switch (dataObj.exists) {
                case false:
                    returnObject = {
                        statusCode: 302,
                        headers: {
                            location: c.OAUTH2_AUTH + "?" + querystring.stringify({
                                response_type: "code",
                                client_id: dataObj.masterSecretValue.client_id,
                                redirect_uri: dataObj.stageVariables.applicationCallbackUrl,
                                scope: dataObj.stageVariables.applicationScope,
                                instance_id: decQs.instance_id,
                                state: decQs.instance_id
                            })
                        },
                        body: JSON.stringify({ result: "OK" })
                    };
                    break;
                case true:
                    returnObject = {
                        body: JSON.stringify(
                            {
                                result: "OK",
                                api_key: dataObj.apiKey
                            })
                    };
                    break;
            }
            return returnObject;
        });
}

function authorization() {
    if (!("code" in qs)) {
        return Promise.reject("Invalid code");
    }
    if (!("state" in qs)) {
        return Promise.reject("Invalid state");
    }
    dataObj.pingIdCode = qs.code;
    dataObj.instance_id = qs.state;
    dataObj.apiKey = crypto.createHash('sha256').update(qs.state).digest('hex');
    dataObj.instance_secret = crypto.createHmac(
        'sha256',
        dataObj.stageVariables.applicationSharedSecret
    ).update(dataObj.apiKey).digest('hex');
    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + dataObj.instance_secret;
    return p.getMasterSecret(dataObj).then(p.pingIdAuth).then(p.createTokens).then(
        () => {
            let bodyResp = { api_key: dataObj.apiKey };
            bodyResp.result = "OK";
            return { body: JSON.stringify(bodyResp) };
        }
    );
}

function tokenOperation() {
    if (!("api_secret" in qs)) {
        return Promise.reject("Missing parameters {api_secret}");
    }
    dataObj.secretName = stageVariables.applicationName + "_" + qs.api_secret;
    switch (dataObj.httpMethod) {
        case c.METHOD_DELETE:
            return p.deleteTokens(dataObj).then(
                () => ({ body: JSON.stringify({ result: "OK" }) }));
        case c.METHOD_GET:
            return p.getTokens(dataObj).then(
                () => {
                    let bodyResp = {
                        access_token: dataObj.tokens.access_token
                    };
                    bodyResp.result = "OK";
                    return { body: JSON.stringify(bodyResp) };
                });
        case c.METHOD_PUT:
            console.log("Refresh tokens call");
            return p.getMasterSecret(dataObj).then(p.getTokens).then(p.pingIdRefresh).then(p.updateTokens).then(
                () => {
                    let bodyResp = {
                        access_token: dataObj.tokens.access_token
                    };
                    bodyResp.result = "OK";
                    return { body: JSON.stringify(bodyResp) };
                });
    }
}

exports.handler = async function (event, context, callback) {
    // Retrieve environmental variables from AWS API Gateway Stage Variables
    stageVariables = event.stageVariables;
    qs = event.queryStringParameters;
    if (stageVariables == null) {
        console.error("Missing API Gateway stage variables {applicationCallbackUrl}, {applicationScope} and {applicationName}");
        callback(null, errorObject("Missing API Gateway stage variables {applicationCallbackUrl}, {applicationScope} and {applicationName}"));
        return;
    }
    if (stageVariables.applicationCallbackUrl == null || stageVariables.applicationCallbackUrl == undefined || stageVariables.applicationCallbackUrl == c.RESOURCE_TOKEN) {
        console.error("Missing or invalid API Gateway stage variable {applicationCallbackUrl}");
        callback(null, errorObject("Missing or invalid API Gateway stage variable {applicationCallbackUrl}"));
        return;
    }
    if (stageVariables.applicationScope == null || stageVariables.applicationScope == undefined) {
        console.error("Missing API Gateway stage variable {applicationScope}");
        callback(null, errorObject("Missing API Gateway stage variable {applicationScope}"));
        return;
    }
    if (stageVariables.applicationName == null || stageVariables.applicationName == undefined) {
        console.error("Missing API Gateway stage variable {applicationName}");
        callback(null, errorObject("Missing API Gateway stage variable {applicationName}"));
        return;
    }

    dataObj.stageVariables = stageVariables;
    dataObj.masterSecret = dataObj.stageVariables.applicationName + "_master";
    let prom = null;

    console.log("Requested Path: " + event.path);
    // Initial Activation
    if (event.path == c.RESOURCE_ACTIVATION && event.httpMethod == c.METHOD_GET) {
        console.log('Application Framework activation request');
        prom = activation();
    }
    // Authorization
    if (event.path == url.parse(stageVariables.applicationCallbackUrl).pathname && event.httpMethod == c.METHOD_GET) {
        console.log('Application Framework authorization request');
        prom = authorization();
    }
    // Token operation
    if (event.path == c.RESOURCE_TOKEN) {
        switch (event.httpMethod) {
            case c.METHOD_DELETE:
            case c.METHOD_GET:
            case c.METHOD_PUT:
                dataObj.httpMethod = event.httpMethod;
                console.log("Application Framework token " + dataObj.httpMethod + " request");
                prom = tokenOperation();
        }
    }

    if (prom == null) {
        prom = Promise.reject("Unknown resource or http method");
    }
    await prom.then(
        response => {
            console.log("Handling OK");
            callback(null, response);
        },
        err => {
            console.log("Handling error: " + err);
            callback(null, errorObject(err));
        }
    );
};

function errorObject(message) {
    return {
        "statusCode": 400,
        "body": JSON.stringify({ result: "ERROR", message: message })
    };
}
