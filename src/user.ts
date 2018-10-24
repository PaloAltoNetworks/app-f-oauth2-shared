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

import { APIGatewayProxyEvent } from 'aws-lambda';
import { newToken } from './lsinstance';
import { parse } from 'querystring';
import { uidGenerator } from './common';
import * as dynamo from './dynamo';
import { createHmac } from 'crypto';

const HOURLYCREATERATE = 60;
const DBPREFIX = 'user';

interface dbItem {
    id: string;
    password: string;
    accountId: string;
}

let sessTimeout: number;
let rateHourBucket = HOURLYCREATERATE;
let lastBucketRefreshHour = 0;
let secret: string;

export async function init(timeout: number, sec: string): Promise<void> {
    sessTimeout = timeout;
    lastBucketRefreshHour = Math.floor(Date.now() / 3600000);
    secret = sec;
}

function cidFactory(): string {
    let currentHour = Math.floor(Date.now() / 3600000);
    if (currentHour > lastBucketRefreshHour) {
        rateHourBucket = HOURLYCREATERATE;
        lastBucketRefreshHour = currentHour;
    }
    if (rateHourBucket == 0) {
        throw Error('max account create rate reached');
    }
    rateHourBucket--;
    return uidGenerator();
}

function hPassword(password: string): string {
    return createHmac('md5', secret).update(password).digest('base64');
}
export async function login(event: APIGatewayProxyEvent): Promise<string> {
    if (event.body == null) {
        throw Error('empty body request');
    }
    let parsedQs = parse(event.body);
    if (!('username' in parsedQs && 'password' in parsedQs)) {
        throw Error('username/password not found in body request');
    }
    let username = parsedQs['username'];
    let password = parsedQs['password'];
    if (!(typeof username == 'string' && typeof password == 'string')) {
        throw Error('invalid username/password in body request');
    }
    let dbElement: dbItem;
    try {
        dbElement = await dynamo.getItem<dbItem>(DBPREFIX, username);
    } catch (e) {
        throw Error('invalid username/password');
    }
    if (hPassword(password) != dbElement.password) {
        throw Error('invalid username/password');
    }
    let cookieUserToken = await newToken(dbElement.accountId, sessTimeout);
    return cookieUserToken;
}

export async function createAccount(event: APIGatewayProxyEvent): Promise<string> {
    if (event.body == null) {
        throw Error('empty request body');
    }
    let parsedBody = parse(event.body);
    if (!('username' in parsedBody && 'password' in parsedBody)) {
        throw Error('username and/or password not found in request body');
    }
    let username = parsedBody['username'];
    let password = parsedBody['password'];
    if (!(typeof username == 'string' && typeof password == 'string')) {
        throw Error('invalid username and/or password in request body');
    }
    let newCustId = cidFactory();
    let alreadyExists: boolean;
    try {
        await dynamo.getItem<dbItem>(DBPREFIX, username);
        alreadyExists = true;
    } catch (e) {
        alreadyExists = false;
    }
    if (alreadyExists) {
        throw Error('account already exists');
    }
    await dynamo.putItem<dbItem>(DBPREFIX, {
        accountId: newCustId,
        id: username,
        password: hPassword(password)
    });
    return newCustId;
}