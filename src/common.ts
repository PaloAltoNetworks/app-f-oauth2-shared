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

import { init as id_init } from './identity';
import { init as dd_init } from './dynamo';
import { init as sm_init } from './secmanager';
import { init as mj_init } from './minijwt';
import { init as to_init } from './token';
import { init as in_init } from './lsinstance';
import { init as us_init } from './user';
import { init as lo_init } from './staticloader';
import { APIGatewayProxyResult, APIGatewayProxyEvent } from 'aws-lambda';
import { createHmac } from 'crypto';
import { stringify } from 'querystring';

let alreadyInit = false;
let mSecret: string;
let uidCounter = 0;
export let baseUri = '/';
let rootBaseUri = true;

export interface masterS {
    client_id: string,
    client_secret: string,
}

export interface tokenS {
    access_token: string,
    expires_utc: number,
    refresh_token: string
}

export async function init(
    prefix: string,
    awsRegion: string,
    secret: string,
    autoR: boolean,
    timeout: number,
    dbTable: string,
    event?: APIGatewayProxyEvent): Promise<void> {
    if (alreadyInit) {
        return;
    }
    dd_init(awsRegion, dbTable);
    sm_init(awsRegion);
    id_init();
    await lo_init();
    await mj_init(secret);
    await to_init(prefix, autoR);
    in_init();
    await us_init(timeout, secret);
    mSecret = secret;
    if (event !== undefined) {
        if (event.path == '/') {
            baseUri = event.requestContext.path;
        } else {
            let parts = new RegExp(`^(.+)${event.path}$`).exec(event.requestContext.path);
            if (!(parts == null || parts.length != 2)) {
                baseUri = parts[1];
            }
        }
        if (baseUri != '/' && (baseUri.length <= 1 || baseUri[baseUri.length - 1] != '/')) {
            rootBaseUri = false;
        }
    }
    alreadyInit = true;
}

export function errorResponse(code: number, message: string): APIGatewayProxyResult {
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Content-Length": message.length
        },
        "body": JSON.stringify({ result: "ERROR", message: message })
    };
}

export function validResponse(message: string, response: object = {}): APIGatewayProxyResult {
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Content-Length": message.length
        },
        "body": JSON.stringify({ result: "OK", message: message, response: response })
    };
}

export function Response200(message: string, contentType: string, head: { [index: string]: string } | null = null): APIGatewayProxyResult {
    let response: {
        statusCode: number, headers: { [index: string]: string | number }, body: string
    } = {
        statusCode: 200,
        headers: {
            "Content-Type": contentType,
            "Content-Length": message.length
        },
        body: message
    };
    if (head != null) {
        Object.entries(head).forEach(e => response.headers[e[0]] = e[1]);
    }
    return response;
}

export function composeUrl(uri: string, qsParams: { [index: string]: string } | null, absolute: boolean = false): string {
    let bUri = absolute ? '' : rootBaseUri ? baseUri : baseUri + '/';
    return (qsParams == null) ? bUri + uri : `${bUri}${uri}?${stringify(qsParams)}`;
}

export function redirectResponse(code: number, uri: string, message: string, qsParams: { [index: string]: string } | null, absolute = false): APIGatewayProxyResult {
    let location = composeUrl(uri, qsParams, absolute);
    return {
        statusCode: code,
        headers: {
            Location: location
        },
        body: JSON.stringify({ result: "SEEOTHER", message: message })
    }
}

export function uidGenerator(): string {
    let value = createHmac('md5', mSecret).update((Date.now() + uidCounter++).toString()).digest('hex');
    return `${value.substring(0, 8)}-${value.substring(8, 16)}-${value.substring(16, 24)}-${value.substring(24, 32)}`;
}
