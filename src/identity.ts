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

import { tokenS } from './common';
import { stringify } from 'querystring';
import { URL } from 'url';
import { request } from 'https';

const TOKEN_URL = "https://api.paloaltonetworks.com/api/oauth2/RequestToken";
const REVOKE_TOKEN_URL = "https://api.paloaltonetworks.com/api/oauth2/RevokeToken";

let tokenUrl: URL;
let revokeUrl: URL;

export function init(ptokenUrl = TOKEN_URL, prtokenUrl = REVOKE_TOKEN_URL): void {
    tokenUrl = new URL(ptokenUrl);
    revokeUrl = new URL(prtokenUrl);
}

/**
 * _Promisification_ of a nodejs https.request POST callback operation
 * @param postBody the POST body
 * @returns the post response text
 */
function urlPromPostRequest(postBody: string, destUrl = tokenUrl): Promise<string> {
    return new Promise((resolve, reject) => {
        let cRequest = request({
            hostname: destUrl.hostname,
            path: destUrl.pathname,
            method: 'POST',
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
                resolve(data);
            });
        }).on("error", err => {
            reject(Error(err.message));
        });
        cRequest.end(postBody);
    });
}

/**
 * Invokes the Identity Manager refresh token operation and return a new token structure
 * @param clientID OAUTH2 client_id
 * @param clientSecret OAUTH2 client_secret
 * @param currentT current token structure that must be refreshed
 * @returns refreshed token structure
 * @throws a promise reject in case the response is not compatible with the tokenS interface or with the
 * exception error provided by {@link JSON.parse} or {@link https.request}
 */
export async function refreshToken(clientID: string, clientSecret: string, currentT: tokenS): Promise<tokenS> {
    let postBody = stringify({
        refresh_token: currentT.refresh_token,
        client_id: clientID,
        client_secret: clientSecret,
        grant_type: "refresh_token"
    });
    let response = JSON.parse(await urlPromPostRequest(postBody));
    // TODO - Remove debug messages
    console.log("Response from PingID\n%j", response);
    if (!('access_token' in response && 'expires_in' in response)) {
        throw Error('invalid response received');
    }
    let newToken: tokenS = {
        access_token: response['access_token'],
        expires_utc: Math.floor(Date.now() / 1000) + parseInt(response['expires_in'], 10),
        refresh_token: currentT.refresh_token
    }
    if ('refresh_token' in response) {
        newToken.refresh_token = response['refresh_token'];
    }
    return newToken;
}

export async function revokeRefreshToken(clientID: string, clientSecret: string, rToken: string): Promise<void> {
    let postBody = stringify({
        token: rToken,
        client_id: clientID,
        client_secret: clientSecret,
        token_type_hint: "refresh_token"
    });
    let response = JSON.parse(await urlPromPostRequest(postBody, revokeUrl));
    console.log("Response from PingID\n%j", response);
}

export async function requestToken(client_id: string, client_secret: string, code: string, callbackUrl: string): Promise<tokenS> {
    let postBody = stringify({
        client_id: client_id,
        client_secret: client_secret,
        code: code,
        redirect_uri: callbackUrl,
        grant_type: "authorization_code"
    });
    let response = JSON.parse(await urlPromPostRequest(postBody));
    // TODO - Remove debug messages
    console.log("Response from PingID\n%j", response);
    if (!('access_token' in response && 'expires_in' in response && 'refresh_token' in response)) {
        throw Error('invalid response received');
    }
    let newToken: tokenS = {
        access_token: response['access_token'],
        expires_utc: Math.floor(Date.now() / 1000) + parseInt(response['expires_in'], 10),
        refresh_token: response['refresh_token']
    }
    return newToken;
}
