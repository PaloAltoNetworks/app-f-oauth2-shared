// Copyright 2015-2017 Palo Alto Networks, Inc
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//       http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

declare function require(name: string);
import * as querystring from "querystring";
import * as crypto from "crypto";
import * as url from "url";
import * as https from "https";

const OAUTH2_AUTH = "https://identity.paloaltonetworks.com/as/authorization.oauth2";
const OAUTH2_TOKEN = "https://identity.paloaltonetworks.com/as/token.oauth2";
const RESOURCE_ACTIVATION = "/";
const RESOURCE_TOKEN = "/token";
const METHOD_GET = "GET";
const METHOD_DELETE = "DELETE";
const METHOD_PUT = "PUT";
const METHOD_POST = "POST";

var qs: { [key: string]: string; };

// -- Embeding AWS JS Stuff
var AWS = require('aws-sdk'),
    region = process.env.AWS_REGION,
    endpoint = "https://secretsmanager." + region + ".amazonaws.com";

console.log("region = " + region);
console.log("endpoint = " + endpoint);

var oauth2TokenURL = url.parse(OAUTH2_TOKEN);

var secretsManagerClient = new AWS.SecretsManager({
    endpoint: endpoint,
    region: region
});
// --

/**
 * Object structure of the object that is chained between promises. Each promise will either read or write properties of this
 * object until the end of the promise chain.
 */
class promiseObjPass {
    exists: boolean;
    httpMethod: string;
    instance_id;
    secretName: string;
    secretDesc: string;
    pingIdCode: string;
    apiKey: string;
    instance_secret: string;
    masterSecret: string;
    masterSecretValue: {
        client_id: string;
        client_secret: string;
    };
    tokens: {
        access_token: string;
        refresh_token: string;
        expires_utc: number;
    };
    stageVariables: {
        applicationCallbackUrl: string;
        applicationSharedSecret: string;
        applicationName: string;
        applicationScope: string;
        applicationWelcomePage: string;
    }
}

interface apiGwResponse {
    statusCode?: number;
    headers?: {
        location: string;
    };
    body: string;
}

var dataObj = new promiseObjPass();

// -- AWS Secrets Manager promises
// Implement CRUD-Like promises to store "secrets" (access_token & refresh_tokens) into AWS Secrets Manager service
// Reimplement these promises to your storage of choice

/**
 * Checks if a given secret already exists in the storage.
 * @param {promiseObjPass} dataObj - chained object between promises. The property _secretName_ will be used as the lookup value.
 * The check will be stored in the _exists_ property of the chained object.
 */
function checkExisting(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Check instance existance " + dataObj.secretName);
        dataObj.exists = false;
        secretsManagerClient.describeSecret({ SecretId: dataObj.secretName }, (err, data) => {
            if (!err) {
                dataObj.exists = true;
            }
            resolve(dataObj);
        });
    }
    );
};

/**
 * Gets the master secret for a given registered application.
 * @param {promiseObjPass} dataObj - chained object between promises. The property _masterSecret_ will be used as the lookup value.
 */
function getMasterSecret(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Calling Secret Manager to fetch " + dataObj.masterSecret);
        secretsManagerClient.getSecretValue({ SecretId: dataObj.masterSecret }, (err, data) => {
            if (err) {
                reject(err.message);
            } else {
                if (data.SecretString !== "") {
                    dataObj.masterSecretValue = JSON.parse(data.SecretString);
                    resolve(dataObj);
                } else {
                    reject("Non-string secret value in " + dataObj.masterSecret);
                }
            }
        });
    }
    );
};

/**
 * Call the Secrets Manager service to fetch a secret by name.
 * @param dataObj - chained object between promises. The property _secretName_ will be used as the lookup value.
 * The _tokens_ property will be updated to include the returned value.
 */
function getTokens(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Calling Secret Manager to fetch " + dataObj.secretName);
        secretsManagerClient.getSecretValue({ SecretId: dataObj.secretName }, (err, data) => {
            if (err) {
                reject(err.message);
            } else {
                if (data.SecretString !== "") {
                    dataObj.tokens = JSON.parse(data.SecretString);
                    resolve(dataObj);
                } else {
                    reject("Non-string secret value in " + dataObj.secretName);
                }
            }
        });
    }
    );
};

/**
 * Add a new secret in the Secrets Manager service
 * @param dataObj - chained object between promises. The property _secretName_ will be used as key and the property _tokens_
 * as the value.
 */
function createTokens(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Calling Secret Manager to create " + dataObj.secretName);
        secretsManagerClient.createSecret({
            Name: dataObj.secretName,
            SecretString: JSON.stringify(dataObj.tokens),
            Description: dataObj.secretDesc
        }, (err, data) => {
            if (err) {
                reject(err.message);
            } else {
                resolve(dataObj);
            }
        });
    });
};

/**
 * Deletes a secret from the Secrets Manager service
 * @param dataObj - chained object between promises. The property _secretManager_ will be used as the index value to be deleted.
 */
function deleteTokens(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Calling Secret Manager to delete " + dataObj.secretName);
        secretsManagerClient.deleteSecret({ SecretId: dataObj.secretName }, (err, data) => {
            if (err) {
                reject(err.message);
            } else {
                resolve(dataObj);
            }
        });
    });
};

/**
 * Updates an existing record in the Secrets Manager service with a refreshed
 * @param dataObj - chained object between promises. The property _secretName_ will be used as key and the property _tokens_
 * as the new value.
 */
function updateTokens(dataObj: promiseObjPass): Promise<promiseObjPass> {
    return new Promise((resolve, reject) => {
        console.log("Calling Secret Manager to update " + dataObj.secretName);
        secretsManagerClient.putSecretValue({
            SecretId: dataObj.secretName,
            SecretString: JSON.stringify(dataObj.tokens)
        }, (err, data) => {
            if (err) {
                reject(err.message);
            } else {
                resolve(dataObj);
            }
        })
    });
};
// --

// -- Palo Alto Networks OAUTH2 PingId promises

/**
 * Used to authorize the application. To change the _code_ for its corresponding *access_token* and *refresh_token* 
 * @param dataObj - chained object between promises. This promise requires the _masterSecretValue_ to be set which means
 * that {@link getMasterSecret} promise must be called before in the promise chain. A successfull execution of this function
 * will store the received tokens into the _tokens_ property and a probable pass to the {@link createSecret} promise will be
 * required.
 * @see getMasterSecret
 * @see createSecret
 */
function pingIdAuth(dataObj: promiseObjPass): Promise<promiseObjPass> {
    console.log("Calling PingID Authorization");
    return new Promise((resolve, reject) => {
        let postBody = querystring.stringify({
            client_id: dataObj.masterSecretValue.client_id,
            client_secret: dataObj.masterSecretValue.client_secret,
            code: dataObj.pingIdCode,
            redirect_uri: dataObj.stageVariables.applicationCallbackUrl,
            grant_type: "authorization_code"
        });
        console.log("Body to send to PingID auth:\n" + postBody);
        let cRequest = https.request({
            hostname: oauth2TokenURL.hostname,
            path: oauth2TokenURL.pathname,
            method: METHOD_POST,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": postBody.length
            }
        }, resp => {
            let data = '';
            resp.on('data', chunk => {
                data += chunk;
            });
            resp.on('end', () => {
                console.log("Response received from PingID:\n" + data);
                let pingIdResponse = JSON.parse(data);
                dataObj.tokens = {
                    access_token: pingIdResponse.access_token,
                    expires_utc: Date.now() + 1000 * pingIdResponse.expires_in,
                    refresh_token: pingIdResponse.refresh_token
                };
                dataObj.secretDesc = "Tokens for instance " + dataObj.instance_id;
                resolve(dataObj);
            });
        }).on("error", err => {
            reject(err.message);
        });
        cRequest.end(postBody);
    });
};

/**
 * User to trigger a token refresh function with the OAUTH2 PingID service.
 * @param dataObj - chained object between promises. The refresh operation requires the function to provide the master secret
 * and the refresh token. This means that before this promise both {@link getMasterSecret} and {@link getTokens} must be
 * called in the promise chain. A successfull call to this function will store the new tokens in the _tokens_ property and a
 * probable pass to {@link updateTokens} promise will be needed.
 * @see getMasterSecret
 * @see getTokens
 * @see updateTokens
 */
function pingIdRefresh(dataObj: promiseObjPass): Promise<promiseObjPass> {
    console.log("Calling PingID Refresh");
    return new Promise((resolve, reject) => {
        let postBody = querystring.stringify({
            refresh_token: dataObj.tokens.refresh_token,
            client_id: dataObj.masterSecretValue.client_id,
            client_secret: dataObj.masterSecretValue.client_secret,
            grant_type: "refresh_token"
        });
        console.log("Body to send to PingID refresh:\n" + postBody);
        let cRequest = https.request({
            hostname: oauth2TokenURL.hostname,
            path: oauth2TokenURL.pathname,
            method: METHOD_POST,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": postBody.length
            }
        }, resp => {
            let data = '';
            resp.on('data', chunk => {
                data += chunk;
            });
            resp.on('end', () => {
                console.log("Response received from PingID:\n" + data);
                let pingIdResponse = JSON.parse(data);
                dataObj.tokens = {
                    access_token: pingIdResponse.access_token,
                    expires_utc: Date.now() + 1000 * pingIdResponse.expires_in,
                    refresh_token: dataObj.tokens.refresh_token
                };
                resolve(dataObj);
            });
        }).on("error", err => {
            reject(err.message);
        });
        cRequest.end(postBody);
    });
};
// --

console.log("Loading Application Framework function");

/**
 * This function provides a way to redirect the user's browser either to the PingID authentication page (first time activation)
 * or to the welcome page (in case the instance_id has already been activated).
 * 
 * It will use the provided *instance_id* value to calculate its corresponding *instance_secret* (index to the Secrets Manager service)
 * for this instance to choose between authorization vs welcome. This means that an invocation to the {@link checkExisting} promise
 * may be needed.
 * 
 * In case a new authorization is needed, a 302 redirect to PingID will be issued and the *instance_id* value will be passed 
 * to PingID in the _state_ queryString parameter (to be captured after the authorization phase is completed to request the tokens).
 * @see checkExisting
 * @see getMasterSecret
 */
function activation(): Promise<apiGwResponse> {
    if (!("params" in qs)) {
        return Promise.reject("Missing activation parameters");
    }
    let decodedParams = Buffer.from(qs["params"], 'base64').toString('ascii');
    let decQs = querystring.parse(decodedParams);
    if (!("instance_id" in decQs)) {
        return Promise.reject("Missing parameters {instance_id}");
    }
    if (!("region" in decQs)) {
        return Promise.reject("Missing parameters {region}");
    }
    dataObj.instance_id = decQs.instance_id;
    dataObj.apiKey = crypto.createHash('sha256').update(<string>decQs["instance_id"]).digest('hex');
    dataObj.instance_secret = crypto.createHmac(
        'sha256',
        dataObj.stageVariables.applicationSharedSecret
    ).update(dataObj.apiKey).digest('hex');
    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + dataObj.instance_secret;
    // Let's get the master secret and redirect the user to AUTH if first time.
    return checkExisting(dataObj).then(getMasterSecret).then(
        () => {
            let returnObject: apiGwResponse;
            switch (dataObj.exists) {
                case false:
                    returnObject = {
                        statusCode: 302,
                        headers: {
                            location: OAUTH2_AUTH + "?" + querystring.stringify({
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
                        statusCode: 302,
                        headers: {
                            location: dataObj.stageVariables.applicationWelcomePage + "?" + querystring.stringify({
                                apikey: dataObj.apiKey
                            })
                        },
                        body: JSON.stringify({ result: "OK" })
                    };
                    break;
            }
            return returnObject;
        });
}

/**
 * Implements a redirect to the welcome page with the API_KEY to be used to perform token operations for this *instance_id*
 * just being authorized. It chaines the promises {@link getMasterSecret}, {@link pingIdAuth} and {@link createTokens} to change
 * the _one time access code_ for its corresponding tokens and storing them.
 * @see getMasterSecret
 * @see pingIdAuth
 * @see createTokens
 */
function authorization(): Promise<apiGwResponse> {
    if (!("code" in qs)) {
        return Promise.reject("Invalid code");
    }
    if (!("state" in qs)) {
        return Promise.reject("Invalid state");
    }
    dataObj.pingIdCode = qs["code"];
    dataObj.instance_id = qs["state"];
    dataObj.apiKey = crypto.createHash('sha256').update(qs["state"]).digest('hex');
    dataObj.instance_secret = crypto.createHmac(
        'sha256',
        dataObj.stageVariables.applicationSharedSecret
    ).update(dataObj.apiKey).digest('hex');
    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + dataObj.instance_secret;
    return getMasterSecret(dataObj).then(pingIdAuth).then(createTokens).then(
        () => ({
            statusCode: 302,
            headers: {
                location: dataObj.stageVariables.applicationWelcomePage + "?" + querystring.stringify({
                    apikey: dataObj.apiKey
                })
            },
            body: JSON.stringify({ result: "OK" })
        })
    );
}

/**
 * Token operations API entry point. The user must provide the madatory *api_secret* queryString parameter (index to the 
 * corresponding secret).
 * 
 * Method supported.
 * - DELETE: To requests the corresponding secret being removed from the storage
 * - GET: To retrieve the current *access_token* and expiration timestamp in the storage.
 * - PUT: To trigger a PingID refresh operations, store the new tokens and provide them back in the response.
 */
function tokenOperation(): Promise<apiGwResponse> {
    if (!("api_secret" in qs)) {
        return Promise.reject("Missing parameters {api_secret}");
    }
    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + qs["api_secret"];
    switch (dataObj.httpMethod) {
        case METHOD_DELETE:
            return deleteTokens(dataObj).then(
                () => ({ body: JSON.stringify({ result: "OK" }) }));
        case METHOD_GET:
            return getTokens(dataObj).then(
                () => {
                    return {
                        body: JSON.stringify({
                            access_token: dataObj.tokens.access_token,
                            expires_utc: dataObj.tokens.expires_utc,
                            result: "OK"
                        })
                    };
                });
        case METHOD_PUT:
            console.log("Refresh tokens call");
            return getMasterSecret(dataObj).then(getTokens).then(pingIdRefresh).then(updateTokens).then(
                () => {
                    return {
                        body: JSON.stringify({
                            access_token: dataObj.tokens.access_token,
                            expires_utc: dataObj.tokens.expires_utc,
                            result: "OK"
                        })
                    };
                });
    }
}

/**
 * Main AWS Lambda Function handler for an AWS API Gateway integration.
 * 
 * Meant to work in _lambda proxy integration_ mode with any request capturing. Will initiate the dataObj object and initiate
 * a promise chain based in the following conditions:
 * - "GET /" : {@link activation}
 * - "GET /<callback>" : {@link authorization}
 * - "DELETE|GET|PUT /token" {@link token}
 */
exports.handler = async function (event, context, callback) {
    // Retrieve environmental variables from AWS API Gateway Stage Variables
    dataObj.stageVariables = event.stageVariables;
    qs = event.queryStringParameters;
    if (qs == null || qs == undefined) {
        console.log("ERROR: This endpoint can't be called with an empty query string");
        callback(null, errorObject("This endpoint can't be called with an empty query string"));
        return;
    }
    if (dataObj.stageVariables == null) {
        console.log("ERROR: Missing API Gateway stage variables");
        callback(null, errorObject("Missing API Gateway stage variables"));
        return;
    }
    [
        "applicationWelcomePage",
        "applicationCallbackUrl",
        "applicationName",
        "applicationSharedSecret",
        "applicationScope"
    ].forEach(v => {
        if (dataObj.stageVariables[v] == null || dataObj.stageVariables[v] == undefined) {
            console.log("ERROR: Missing or invalid API Gateway stage variable {" + v + "}");
            callback(null, errorObject("Missing or invalid API Gateway stage variable {" + v + "}"));
            return;
        }
    }
    );

    dataObj.masterSecret = dataObj.stageVariables.applicationName + "_master";
    let prom: Promise<apiGwResponse>;

    console.log("Requested Path: " + event.path);
    // Initial Activation
    if (event.path == RESOURCE_ACTIVATION && event.httpMethod == METHOD_GET) {
        console.log('Application Framework activation request');
        prom = activation();
    }
    // Token operation
    if (event.path == RESOURCE_TOKEN) {
        switch (event.httpMethod) {
            case METHOD_DELETE:
            case METHOD_GET:
            case METHOD_PUT:
                dataObj.httpMethod = event.httpMethod;
                console.log("Application Framework token " + dataObj.httpMethod + " request");
                prom = tokenOperation();
        }
    }
    // Neither the root path (RESOURCE_ACTIVATION) neither the token entry point. Let's assume it is a callback call
    if (prom == null) {
        if (event.httpMethod == METHOD_GET) {
            console.log('Application Framework authorization request');
            prom = authorization();
        } else {
            prom = Promise.reject("Unknown resource or http method");
        }
    }
    await prom.then(
        response => {
            console.log("Handling OK");
            callback(null, response);
        },
        err => {
            console.log("ERROR: Handling error: " + err);
            callback(null, errorObject(err));
        }
    );
};

function errorObject(message): apiGwResponse {
    return {
        "statusCode": 400,
        "body": JSON.stringify({ result: "ERROR", message: message })
    };
}
