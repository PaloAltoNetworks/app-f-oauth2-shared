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

import { tokenS, masterS } from './common';
import * as minijwt from './minijwt';
import * as identity from './identity';
import * as secManager from './secmanager';

const EXPIRATION_GUARD = 300;
export const JWTISS = 'api';

let clientSecret: string;
export let clientID: string = "";
let autoRefresh: boolean;
let smPrefix: string;

export async function init(prefix: string, autoR = true): Promise<void> {
    let masterName = prefix + '_master';
    smPrefix = prefix;
    let masterSecret = await getMasterSecret(masterName);
    clientID = masterSecret.client_id;
    clientSecret = masterSecret.client_secret;
    autoRefresh = autoR;
}

async function getMasterSecret(secretName: string): Promise<masterS> {
    let secretObject = await secManager.smPromGetSecretValue<masterS>(secretName);
    if (!('client_id' in secretObject && 'client_secret' in secretObject)) {
        throw Error('Master Secret retrieved has invalid format');
    }
    return { client_id: secretObject['client_id'], client_secret: secretObject['client_secret'] };
}

async function getTokenSecret(tokenName: string): Promise<tokenS> {
    let secret = await secManager.smPromGetSecretValue<tokenS>(smPrefix + '_' + tokenName);
    if (!('access_token' in secret && 'expires_utc' in secret && 'refresh_token' in secret)
        || isNaN(secret['expires_utc'])) {
        throw Error('Token Secret retrieved has invalid format');
    }
    return {
        access_token: secret['access_token'],
        expires_utc: secret['expires_utc'],
        refresh_token: secret['refresh_token']
    };
}

async function internalRefreshToken(tokenID: string, tokenEntry: tokenS): Promise<tokenS> {
    let newTokenS = await identity.refreshToken(clientID, clientSecret, tokenEntry);
    await secManager.smPromUpdateSecretValue(smPrefix + '_' + tokenID, newTokenS);
    return newTokenS;
}

export async function refreshToken(authToken: string): Promise<string> {
    let payload = await minijwt.payload(authToken, JWTISS);
    let tokenID = payload.sub;
    let tokenEntry = await getTokenSecret(tokenID);
    let newT = await internalRefreshToken(tokenID, tokenEntry);
    return newT.access_token;
}

export async function getAccessToken(authToken: string): Promise<string> {
    let payload = await minijwt.payload(authToken, JWTISS);
    let tokenID = payload.sub;
    let tokenEntry = await getTokenSecret(tokenID);
    if ((Math.floor(Date.now() / 1000) - EXPIRATION_GUARD) > tokenEntry.expires_utc && autoRefresh) {
        let newT = await internalRefreshToken(tokenID, tokenEntry);
        tokenEntry = newT;
    }
    return tokenEntry.access_token;
}
export async function exchangeCode(code: string, callbackUrl: string, instId: string, desc: string): Promise<void> {
    let tokens = await identity.requestToken(clientID, clientSecret, code, callbackUrl);
    try {
        await secManager.smPromCreateSecret(smPrefix + '_' + instId, tokens, desc);
    } catch (e) {
        if (e.message == 'ResourceExistsException') {
            await secManager.smPromUpdateSecretValue(smPrefix + '_' + instId, tokens);
        } else {
            throw Error(e.message);
        }
    }
}

export function newToken(sub: string, validSeconds: number): Promise<string> {
    let expiration = Math.floor(Date.now() / 1000) + validSeconds;
    return minijwt.newToken(sub, expiration, JWTISS)
}

export function revoke(authToken: string): Promise<void> {
    return minijwt.revoke(authToken);
}
