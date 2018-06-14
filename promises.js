'use strict';

(function () {
    const c = require('consts');
    const https = require('https');
    const url = require('url');

    var AWS = require('aws-sdk'),
        region = process.env.AWS_REGION,
        endpoint = "https://secretsmanager." + region + ".amazonaws.com";

    console.log("region = " + region);
    console.log("endpoint = " + endpoint);

    var oauth2TokenURL = url.parse(c.OAUTH2_TOKEN);

    var client = new AWS.SecretsManager({
        endpoint: endpoint,
        region: region
    });

    // AWS Secrets Manager promises
    module.exports.getMasterSecret = dataObj => {
        return new Promise((resolve, reject) => {
            console.log("Calling Secret Manager to fetch " + dataObj.masterSecret);
            client.getSecretValue({ SecretId: dataObj.masterSecret }, (err, data) => {
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

    module.exports.getTokens = dataObj => {
        return new Promise((resolve, reject) => {
            console.log("Calling Secret Manager to fetch " + dataObj.secretName);
            client.getSecretValue({ SecretId: dataObj.secretName }, (err, data) => {
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

    module.exports.createTokens = dataObj => {
        return new Promise((resolve, reject) => {
            console.log("Calling Secret Manager to create " + dataObj.secretName);
            client.createSecret({
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

    module.exports.deleteTokens = dataObj => {
        return new Promise((resolve, reject) => {
            console.log("Calling Secret Manager to delete " + dataObj.secretName);
            client.deleteSecret({ SecretId: dataObj.secretName }, (err, data) => {
                if (err) {
                    reject(err.message);
                } else {
                    resolve(dataObj);
                }
            });
        });
    };

    module.exports.updateTokens = dataObj => {
        return new Promise((resolve, reject) => {
            console.log("Calling Secret Manager to update " + dataObj.secretName);
            client.putSecretValue({
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

    // pingId promises
    module.exports.pingIdAuth = dataObj => {
        console.log("Calling PingID Authorization");
        return new Promise((resolve, reject) => {
            let postBody = JSON.stringify({
                code: dataObj.pingIdCode,
                redirect_uri: dataObj.stageVariables.applicationCallbackUrl,
                grant_type: "authorization_code",
                client_id: dataObj.masterSecretValue.client_id,
                client_secret: dataObj.masterSecretValue.client_secret
            });
            console.log("Body to send to PingID auth:\n" + postBody);
            let cRequest = https.request({
                hostname: oauth2TokenURL.hostname,
                path: oauth2TokenURL.pathname,
                method: c.METHOD_POST,
                headers: {
                    "Content-Type": "application/json",
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
                    dataObj.tokens = { access_token: pingIdResponse.access_token, refresh_token: pingIdResponse.refresh_token };
                    dataObj.secretName = dataObj.stageVariables.applicationName + "_" + dataObj.instance_secret;
                    dataObj.secretDesc = "Tokens for instance " + dataObj.instance_id;
                    resolve(dataObj);
                });
            }).on("error", err => {
                reject(err.message);
            });
            cRequest.end(postBody);
        });
    };

    module.exports.pingIdRefresh = dataObj => {
        console.log("Calling PingID Refresh");
        return new Promise((resolve, reject) => {
            let postBody = JSON.stringify({
                refresh_token: dataObj.tokens.refresh_token,
                grant_type: "refresh_token",
                client_id: dataObj.masterSecretValue.client_id,
                client_secret: dataObj.masterSecretValue.client_secret
            });
            console.log("Body to send to PingID refresh:\n" + postBody);
            let cRequest = https.request({
                hostname: oauth2TokenURL.hostname,
                path: oauth2TokenURL.pathname,
                method: c.METHOD_POST,
                headers: {
                    "Content-Type": "application/json",
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
                    dataObj.tokens = { access_token: pingIdResponse.access_token, refresh_token: pingIdResponse.refresh_token };
                    resolve(dataObj);
                });
            }).on("error", err => {
                reject(err.message);
            });
            cRequest.end(postBody);
        });
    };
}());
