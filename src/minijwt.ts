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

import { createHmac } from "crypto";
import * as dynamo from './dynamo';

const ID = 'revocation';
const DBPREFIX = 'mjwt';
export const MINIJWTERR = 'minijwterror';
const MAXCHECKCACHE = 1000;
const CHECKCACHEGBBLOCK = 100;

interface dbItem {
    id: string;
    seq: number;
    tokenList: string[];
}

export interface miniToken {
    sub: string;
    exp: number;
    jti: number;
    iss: string;
}

class minijwterror extends Error {
    constructor(message: string) {
        super(message);
        this.name = MINIJWTERR;
    }
}

let header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'; // base64({ alg: 'HS256', typ: 'JWT' })
let memCache: string[];
let checkCache: string[];
let sigFuncs: { [i: string]: (c: string) => string }

export async function init(issuers: { [i: string]: string }): Promise<void> {
    memCache = [];
    checkCache = [];
    sigFuncs = {};
    for (let [i, s] of Object.entries(issuers)) {
        sigFuncs[i] = function (content: string): string { return signature(content, s) }
    }
}

function signature(content: string, secret: string): string {
    let c = createHmac('sha256', secret);
    c.update(content);
    return c.digest('base64');
}

function checkSignature(signString: string, signValue: string, signF: (c: string) => string): boolean {
    let combo = signString + ":" + signValue;
    if (checkCache.includes(combo)) {
        return true
    }
    let matched = signF(signString) == signValue;
    if (matched) {
        checkCache.push(combo);
        if (checkCache.length > MAXCHECKCACHE) {
            checkCache.splice(0, CHECKCACHEGBBLOCK);
        }
    }
    return matched;
}

// TODO: make method private after development phase is completed
export function tokenize(payload: miniToken): string {
    if (!('sub' in payload && 'exp' in payload && 'jti' in payload && 'iss' in payload)) {
        throw new minijwterror('invalid payload');
    }
    if (!(payload.iss in sigFuncs)) {
        throw new minijwterror('unknown issuer');
    }
    let pClone: miniToken = {
        exp: payload.exp,
        sub: payload.sub,
        jti: payload.jti,
        iss: payload.iss
    }
    let b64payload = Buffer.from(JSON.stringify(pClone)).toString('base64');
    let signString = header + '.' + b64payload;
    return signString + '.' + sigFuncs[payload.iss](signString);
}

async function dbRevoked(token: string): Promise<boolean> {
    let revList = await dynamo.getSafeItem<dbItem>(DBPREFIX, ID, { id: ID, seq: 0, tokenList: [] });
    return revList.tokenList.includes(token);
}

export async function payload(token: string, expectedIssuer: string): Promise<miniToken> {
    if (await dbRevoked(token) || memCache.includes(token)) {
        throw new minijwterror('revoked token');
    }
    if (!(expectedIssuer in sigFuncs)) {
        throw new minijwterror('unknown issuer');
    }
    let parts = token.split('.');
    if (parts.length != 3 || !checkSignature(parts[0] + '.' + parts[1], parts[2], sigFuncs[expectedIssuer])) {
        throw new minijwterror('invalid token');
    }
    let payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    if (!('sub' in payload && 'exp' in payload && 'jti' in payload && 'iss' in payload) || isNaN(payload['exp'])) {
        throw new minijwterror('missing/invalid "sub" and/or "exp" and/or "jti" and/or "iss" attribute(s) in the payload');
    }
    if (payload['exp'] < Math.floor(Date.now() / 1000)) {
        throw new minijwterror('expired token');
    }
    if (payload['iss'] != expectedIssuer) {
        throw new minijwterror('invalid issuer');
    }
    let castedPayload: miniToken = {
        exp: payload['exp'],
        sub: payload['sub'],
        jti: payload['jti'],
        iss: payload['iss']
    };
    return castedPayload
}

export async function newToken(sub: string, exp: number, iss: string): Promise<string> {
    let revList = await dynamo.getSafeItem<dbItem>(DBPREFIX, ID, { id: ID, seq: 0, tokenList: [] });
    let newToken = tokenize({
        sub: sub,
        exp: exp,
        jti: revList.seq++,
        iss: iss
    });
    await dynamo.putItem<dbItem>(DBPREFIX, revList);
    return newToken;
}

export function mrevoke(token: string): void {
    memCache.push(token);
    if (memCache.length > MAXCHECKCACHE) {
        memCache.splice(0, CHECKCACHEGBBLOCK);
    }

}

export async function revoke(token: string): Promise<void> {
    let revList = await dynamo.getSafeItem<dbItem>(DBPREFIX, ID, { id: ID, seq: 0, tokenList: [] });
    if (revList.tokenList.includes(token)) {
        return;
    }
    revList.tokenList.push(token);
    await dynamo.putItem<dbItem>(DBPREFIX, revList);
    return;
}
