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

import * as mjwt from './minijwt';
import * as dynamo from './dynamo';
import * as token from './token';
import { uidGenerator, redirectResponse } from './common';
import { APIGatewayProxyResult } from 'aws-lambda';

const DBPREFIX = 'inst';
const OAUTH2_TOKEN = 'https://identity.paloaltonetworks.com/as/authorization.oauth2';
export const JWTISS = 'usr';
export const ERRCIDEXISTS = 'client id already exists';
export const ERRIIDEXISTS = 'instance id already exists';
export const ERRTIDEXISTS = 'token id already exists';
export const ERRUNKNCID = 'unknown client id';
export const ERRUNKNIID = 'unknown instance id';
export const ERRUNKNTID = 'unknown token id';
export const ERRREMINS = 'instance contains valid tokens';

export interface apitoken {
    value: string;
    subject: string,
    expiration: number;
    revoked: boolean;
}

interface lsinst {
    instanceId: string;
    description: string;
    activated: boolean;
    region: string;
    apitok: {
        [index: string]: apitoken
    }
}

interface dbItem {
    id: string;
    lsinst: {
        [index: string]: lsinst;
    }
}

export interface toExpire {
    seconds: number,
    sub: string
}

export interface apiTokenGenerated {
    id: string,
    value: string,
    expiration: number
}

interface dbCodeRequests {
    id: string,
    request: { [index: string]: { instance: string, description: string } }
}

let identityUrl: string;

export function init(idUrl = OAUTH2_TOKEN): void {
    identityUrl = idUrl;
}

async function loadAccount(account: string): Promise<dbItem> {
    return await dynamo.getItem<dbItem>(DBPREFIX, account);
}

export async function createClient(authToken: string): Promise<void> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let clientID = payload.sub;
    let checkAccountError: string | null = null;
    try {
        await loadAccount(clientID);
        checkAccountError = "client already exists";
    } catch (e) {
        if (e.message != dynamo.DBERROREMPTY) {
            checkAccountError = e.message
        }
    }
    if (checkAccountError != null) {
        throw Error(ERRCIDEXISTS);
    }
    let newClient: dbItem = {
        id: clientID,
        lsinst: {}
    }
    await storeAccount(newClient);
}

async function storeAccount(dbI: dbItem): Promise<void> {
    await dynamo.putItem<dbItem>(DBPREFIX, dbI);
}

export async function getClient(authToken: string): Promise<{ custId: string, instances: { [index: string]: lsinst } }> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let clientID = payload.sub;
    let c = await loadAccount(clientID);
    return { custId: clientID, instances: c.lsinst };
}

export async function addInstance(authToken: string, instanceID: string, region: string, description: string): Promise<string> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(Object.keys(c.lsinst).every(i => c.lsinst[i].instanceId != instanceID))) {
        throw Error('instance already exists');
    }
    let uid = uidGenerator();
    c.lsinst[uid] = {
        instanceId: instanceID,
        activated: false,
        apitok: {},
        region: region,
        description: description
    };
    await storeAccount(c);
    return uid;
}

function isInvalid(apit: apitoken): boolean {
    return apit.revoked || apit.expiration < Math.floor(Date.now() / 1000);
}

export async function removeInstance(authToken: string, instanceID: string): Promise<void> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instanceID in c.lsinst)) {
        throw Error(ERRUNKNIID);
    }
    let apiTokens = Object.keys(c.lsinst[instanceID].apitok);
    if (apiTokens.length == 0 || apiTokens.every(i => isInvalid(c.lsinst[instanceID].apitok[i]))) {
        delete c.lsinst[instanceID];
        await storeAccount(c);
        return
    }
    throw Error(ERRREMINS);
}

export async function addToken(authToken: string, instanceID: string, tokenSubject: string, validSeconds: number): Promise<apiTokenGenerated> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instanceID in c.lsinst)) {
        throw Error(ERRUNKNIID);
    }
    let tokenID = uidGenerator();
    let newAT = await token.newToken(c.lsinst[instanceID].instanceId, validSeconds);
    let expires = Math.floor(Date.now() / 1000) + validSeconds;
    c.lsinst[instanceID].apitok[tokenID] = {
        expiration: expires,
        revoked: false,
        value: newAT,
        subject: tokenSubject
    };
    await storeAccount(c);
    return {
        expiration: expires,
        id: tokenID,
        value: newAT
    };
}

export async function removeToken(authToken: string, instanceID: string, tokenID: string): Promise<void> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instanceID in c.lsinst)) {
        throw Error(ERRUNKNIID);
    }
    if (!(tokenID in c.lsinst[instanceID].apitok)) {
        throw Error(ERRUNKNTID);
    }
    if (Math.floor(Date.now() / 1000) < c.lsinst[instanceID].apitok[tokenID].expiration) {
        await token.revoke(c.lsinst[instanceID].apitok[tokenID].value);
    }
    delete c.lsinst[instanceID].apitok[tokenID]
    await storeAccount(c);
}

export async function revokeToken(authToken: string, instanceID: string, tokenID: string): Promise<void> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instanceID in c.lsinst)) {
        throw Error(ERRUNKNIID);
    }
    if (!(tokenID in c.lsinst[instanceID].apitok)) {
        throw Error(ERRUNKNTID);
    }
    if (isInvalid(c.lsinst[instanceID].apitok[tokenID])) {
        throw Error('token is already invalid');
    }
    await token.revoke(c.lsinst[instanceID].apitok[tokenID].value);
    c.lsinst[instanceID].apitok[tokenID].revoked = true;
    await storeAccount(c);
}

export function newToken(sub: string, validSeconds: number): Promise<string> {
    let expiration = Math.floor(Date.now() / 1000) + validSeconds;
    return mjwt.newToken(sub, expiration, JWTISS)
}

export function clearToken(token: string): void {
    mjwt.mrevoke(token);
}

export async function checkToken(token: string): Promise<toExpire | null> {
    let tokenPayload: mjwt.miniToken;
    try {
        tokenPayload = await mjwt.payload(token, JWTISS)
    } catch {
        return null;
    }
    return { seconds: tokenPayload.exp - Math.floor(Date.now() / 1000), sub: tokenPayload.sub };
}

export async function actRequest(authToken: string, instID: string,
    callbackUrl: string, scope: string): Promise<APIGatewayProxyResult> {
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instID in c.lsinst) || c.lsinst[instID].activated) {
        throw Error('instance not found or already activated');
    }
    let reqUid = uidGenerator();
    let cr = await dynamo.getSafeItem<dbCodeRequests>(DBPREFIX, 'coderequests', { id: 'coderequests', request: {} })
    cr.request[reqUid] = { instance: instID, description: c.lsinst[instID].description };
    await dynamo.putItem<dbCodeRequests>(DBPREFIX, cr);
    let qsParams: { [index: string]: string } = {
        response_type: 'code',
        client_id: token.clientID,
        redirect_uri: callbackUrl,
        scope: scope,
        instance_id: c.lsinst[instID].instanceId,
        state: reqUid
    }
    return redirectResponse(303, identityUrl, 'sending user to PingID ...', qsParams, true);
}

export async function authCallback(authToken: string, code: string, state: string, callbackUrl: string): Promise<APIGatewayProxyResult> {
    let cr = await dynamo.getSafeItem<dbCodeRequests>(DBPREFIX, 'coderequests', { id: 'coderequests', request: {} })
    if (!(state in cr.request)) {
        let errMessage = 'unsolicited callback code received';
        return redirectResponse(302, '', errMessage, { act_error: errMessage });
    }
    let instance = cr.request[state];
    delete cr.request[state];
    await dynamo.putItem<dbCodeRequests>(DBPREFIX, cr);
    let payload = await mjwt.payload(authToken, JWTISS);
    let c = await loadAccount(payload.sub);
    if (!(instance.instance in c.lsinst)) {
        let errMessage = 'instance to activate unknown';
        return redirectResponse(302, '', errMessage, { act_error: errMessage });
    }
    try {
        await token.exchangeCode(code, callbackUrl, c.lsinst[instance.instance].instanceId, instance.description);
    } catch (e) {
        console.log("Code exchange error:\%j", e.message);
        let errMessage = 'internal error on activation';
        return redirectResponse(302, '', errMessage, { err: errMessage });
    }
    c.lsinst[instance.instance].activated = true;
    await storeAccount(c)
    return redirectResponse(302, '', '', null);
}