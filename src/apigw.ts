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
import {
    APIGatewayProxyEvent,
    APIGatewayProxyCallback,
    APIGatewayEventRequestContext,
    APIGatewayProxyResult
} from 'aws-lambda';
import * as comm from './common';
import * as tokMgr from './token';
import * as insMgr from './lsinstance';
import * as usrMgr from './user';
import * as qs from 'querystring';
import { stContent } from './staticloader';

interface bearerExtract {
    extracted: boolean;
    errorCode: number;
    errorMessaje: string;
    token: string;
}

interface appParams {
    instance_id: string;
    region: string;
    lsalias: string;
}

function getCookiesFromHeader(headers: { [index: string]: string }): { [index: string]: string } {
    if (headers === null || headers === undefined || (headers.cookie === undefined && headers.Cookie === undefined)) {
        return {};
    }
    let cookieString = (headers.cookie === undefined) ? 'Cookie' : 'cookie';
    let list: { [index: string]: string } = {};
    let rc = headers[cookieString];

    rc && rc.split(';').forEach(cookie => {
        var parts = cookie.split('=');
        var key = parts.shift();
        if (typeof key === "undefined") {
            return;
        }
        key = key.trim();
        var value = decodeURI(parts.join('='));
        if (key != '') {
            list[key] = value
        }
    });
    return list;
};

function tokenExtract(event: APIGatewayProxyEvent, cookie: string): bearerExtract {
    let extract: bearerExtract = {
        errorCode: 401,
        errorMessaje: 'Unable to find Authorization Data',
        extracted: false,
        token: ''
    }
    let cookies = getCookiesFromHeader(event.headers);
    if (cookie in cookies) {
        extract = { errorCode: 0, errorMessaje: '', extracted: true, token: cookies[cookie] };
    }
    if ('Authorization' in event.headers) {
        let extraction = /^Bearer (.*)$/.exec(event.headers['Authorization']);
        if (extraction == null || extraction.length != 2) {
            extract = { errorCode: 401, errorMessaje: 'Invalid Authorization', extracted: false, token: '' };
        } else {
            extract = { errorCode: 0, errorMessaje: '', extracted: true, token: extraction[1] };
        }
    }
    return extract;
}

function decodeAppFramParams(params: string): appParams {
    let decodedParams = Buffer.from(params, 'base64').toString('ascii');
    let parsedParams = qs.parse(decodedParams);
    if (!('instance_id' in parsedParams && typeof parsedParams['instance_id'] == 'string')) {
        throw Error('mandatory [instance_id] string param is missing');
    }
    let response: appParams = { instance_id: parsedParams['instance_id'] as string, lsalias: '#', region: '#' };
    if (!('region' in parsedParams && typeof parsedParams['region'] == 'string')) {
        throw Error('mandatory [region] string param is missing');
    }
    response.region = parsedParams['region'] as string;
    if ('lsalias' in parsedParams && typeof parsedParams['lsalias'] == 'string') {
        response.lsalias = parsedParams['lsalias'] as string;
    } else {
        response.lsalias = response.instance_id;
    }
    return response;
}

exports.handler = async function (
    event: APIGatewayProxyEvent,
    context: APIGatewayEventRequestContext,
    callback: APIGatewayProxyCallback): Promise<APIGatewayProxyResult> {

    let presets: { [index: string]: (x: string | null | undefined) => string | number | boolean } = {
        'MASTERSECRET': x => (x == null || x === undefined) ? 'yjnKx4tGmE' : x,
        'SMPREFIX': x => (x == null || x === undefined) ? 'oa2s' : x,
        'DBTABLE': x => (x == null || x === undefined) ? 'oa2s' : x,
        'AUTOREFRESH': x => (x == 'true' || x == 'True' || x == 'TRUE' || x == 'yes' || x == 'Yes' || x == 'YES') ? true : false,
        'SESSTOUT': x => (isNaN(parseInt(x as string, 10))) ? 1800 : parseInt(x as string, 10),
        'SESSGUARD': x => (isNaN(parseInt(x as string, 10))) ? 300 : parseInt(x as string, 10),
        'COOKIENAME': x => (x == null || x === undefined) ? 'oauth2shared' : x,
        'SCOPE': x => (x == null || x === undefined) ? '' : x
    }
    let stageVar = event.stageVariables;
    let configValues: { [index: string]: string | number | boolean } = {};
    Object.entries(presets).forEach(e => { configValues[e[0]] = e[1](stageVar == null ? null : stageVar[e[0]]) });

    let awsRegion = process.env['AWS_REGION'];
    if (awsRegion == undefined) {
        return comm.errorResponse(500, 'unknown AWS_REGION');
    }

    try {
        await comm.init(configValues['SMPREFIX'] as string,
            awsRegion,
            configValues['MASTERSECRET'] as string,
            configValues['AUTOREFRESH'] as boolean,
            configValues['SESSTOUT'] as number,
            configValues['DBTABLE'] as string,
            event);
    } catch (e) {
        console.log("ERROR(internal): %s\n%j", e.message, e);
        return comm.errorResponse(500, 'Internal Error');
    }

    let queryString = event.queryStringParameters;
    let callbackUrl = `https://${event.headers["Host"]}${comm.composeUrl('callback', null)}`;
    let parsedBody: any;
    if (typeof event.body == 'string') {
        try {
            parsedBody = JSON.parse(event.body);
        } catch (e) {
            parsedBody = null;
        }
    }
    let tokenEx = tokenExtract(event, configValues['COOKIENAME'] as string);
    // Operations that do not require Authentication Token
    let staticContent: string;
    try {
        switch (`${event.httpMethod}:${event.path}`) {
            case 'GET:/loginsrv.js': {
                return comm.Response200(stContent['loginsrv.js'], 'text/javascript');
            }
            case 'GET:/oa2sclient.js':
            case 'GET:/prod/oa2sclient.js': {
                return comm.Response200(stContent['oa2sclient.js'], 'text/javascript');
            }
            case 'GET:/appvue.js':
            case 'GET:/prod/appvue.js': {
                return comm.Response200(stContent['appvue.js'], 'text/javascript');
            }
            case 'GET:/': {
                if (tokenEx.extracted && await insMgr.checkToken(tokenEx.token) != null) {
                    return comm.Response200(stContent['apppage.html'], 'text/html');
                }
                return comm.redirectResponse(302, 'login', '', queryString);
            }
            case 'GET:/login': {
                if (tokenEx.extracted && await insMgr.checkToken(tokenEx.token) != null) {
                    return comm.redirectResponse(302, '', '', queryString);
                }
                return comm.Response200(stContent['loginpage.html'], 'text/html');
            }
            case 'POST:/logingen': {
                let uToken: string;
                try {
                    uToken = await usrMgr.login(event);
                    return comm.validResponse("login successful", { 'Bearer': uToken });
                } catch (e) {
                    return comm.errorResponse(401, e.message);
                }
            }
            case 'POST:/login': {
                let uToken: string;
                try {
                    uToken = await usrMgr.login(event);
                    let cookieUserToken = encodeURI(uToken);
                    let loc = comm.baseUri;
                    if (queryString != null) {
                        loc += '?' + qs.stringify(queryString);
                    }
                    return {
                        statusCode: 303,
                        headers: {
                            Location: loc,
                            "Set-Cookie": `${configValues['COOKIENAME']}=${cookieUserToken}; Max-Age=${configValues['SESSTOUT']}; Path=/`
                        },
                        body: ''
                    }
                } catch (e) {
                    let respObj: { [index: string]: string } = {};
                    if (queryString != null) {
                        respObj = queryString;
                    }
                    respObj['err'] = e.message;
                    return comm.redirectResponse(303, 'login', e.message, respObj);
                }
            }
            case 'POST:/login/create': {
                try {
                    let newCustomerID = await usrMgr.createAccount(event);
                    let newSessionToken = await insMgr.newToken(newCustomerID, configValues['SESSTOUT'] as number);
                    await insMgr.createClient(newSessionToken);
                    let loc = comm.baseUri;
                    if (queryString != null) {
                        loc += '?' + qs.stringify(queryString);
                    }
                    return {
                        body: '',
                        statusCode: 302,
                        headers: {
                            Location: loc,
                            "Set-Cookie": `${configValues['COOKIENAME']}=${newSessionToken}; Max-Age=${configValues['SESSTOUT']}; Path=/`
                        }
                    }
                } catch (e) {
                    return comm.redirectResponse(302, 'login', e.message, { err: e.message });
                }
            }
            case 'GET:/appframe': {
                if (!(queryString != null && 'params' in queryString)) {
                    return comm.redirectResponse(302, '', 'missing [params]', null);
                }
                let dParams = decodeAppFramParams(queryString['params']);
                if (tokenEx.extracted && await insMgr.checkToken(tokenEx.token) != null) {
                    try {
                        await insMgr.addInstance(
                            tokenEx.token,
                            dParams.instance_id,
                            dParams.region,
                            dParams.lsalias
                        );
                    } finally {
                        return comm.redirectResponse(302, '', '', null);
                    }
                }
                return comm.redirectResponse(302, 'login', dParams.instance_id, {
                    cmd: 'create',
                    instance_id: dParams.instance_id,
                    region: dParams.region,
                    description: dParams.lsalias
                });
            }
        }
    } catch (e) {
        console.log("ERROR(internal): %s\n%j", e.message, e);
        return comm.errorResponse(500, e.message);
    }

    // Operations that require an Authentication Token
    if (!tokenEx.extracted) {
        return comm.errorResponse(tokenEx.errorCode, tokenEx.errorMessaje);
    }

    try {
        let response: (null | APIGatewayProxyResult) = null;
        switch (`${event.httpMethod}:${event.path}`) {
            case 'POST:/logout': {
                insMgr.clearToken(tokenEx.token);
                return comm.redirectResponse(302, 'login', '', null);
            }
            case 'GET:/callback': {
                if (!(queryString != null && 'code' in queryString && 'state' in queryString)) {
                    let errMessage = 'mandatory fields [code, state] not provided';
                    response = comm.redirectResponse(302, '', errMessage, { act_error: errMessage });
                } else {
                    response = await insMgr.authCallback(tokenEx.token, queryString['code'], queryString['state'], callbackUrl);
                }
                break;
            }
            case "GET:/token": {
                response = comm.validResponse('operation successful', { access_token: await tokMgr.getAccessToken(tokenEx.token) });
                break;
            }
            case "GET:/token/refresh": {
                response = comm.validResponse('operation successful', { access_token: await tokMgr.refreshToken(tokenEx.token) });
                break;
            }
            case "GET:/token/revoke": {
                await tokMgr.revoke(tokenEx.token);
                response = comm.validResponse('token revoked');
                break;
            }
            case "GET:/db": {
                response = comm.validResponse("retrieved customer data", await insMgr.getClient(tokenEx.token));
                break;
            }
            case "POST:/db/instance": {
                if (!(parsedBody != null && 'instance' in parsedBody &&
                    'region' in parsedBody && 'description' in parsedBody)) {
                    response = comm.errorResponse(400, 'mandatory fields [intance, region, description] not found in request body');
                } else {
                    let uid = await insMgr.addInstance(tokenEx.token, parsedBody['instance'],
                        parsedBody['region'], parsedBody['description']);
                    response = comm.validResponse("new instance created", { instId: uid });
                }
                break;
            }
            case "DELETE:/db/instance": {
                if (!(parsedBody != null && 'instance' in parsedBody)) {
                    response = comm.errorResponse(400, 'mandatory field [intance] not found in request body');
                } else {
                    await insMgr.removeInstance(tokenEx.token, parsedBody['instance']);
                    response = comm.validResponse("instance ID removed");
                }
                break;
            }
            case "GET:/db/instance/activate": {
                if (!(queryString != null && 'instance' in queryString)) {
                    response = comm.errorResponse(400, 'mandatory field [intance] not found in request body');
                } else {
                    let instanceId = queryString['instance'];
                    response = await insMgr.actRequest(tokenEx.token, instanceId, callbackUrl, configValues['SCOPE'] as string);
                }
                break;
            }
            case "POST:/db/instance/token": {
                if (!(parsedBody != null && 'instance' in parsedBody && 'maxage' in parsedBody && 'subject' in parsedBody)) {
                    response = comm.errorResponse(400, 'mandatory fields [intance, maxage, subject] not found in request body');
                } else {
                    let maxage = parseInt(parsedBody['maxage'], 10);
                    if (isNaN(maxage)) {
                        response = comm.errorResponse(400, '"maxage" is not a number');
                    } else {
                        let newAT = await insMgr.addToken(tokenEx.token,
                            parsedBody['instance'], parsedBody['subject'], maxage);
                        response = comm.validResponse("new token created", newAT);
                    }
                }
                break;
            }
            case "DELETE:/db/instance/token": {
                if (!(parsedBody != null && 'instance' in parsedBody && 'token' in parsedBody)) {
                    response = comm.errorResponse(400, 'mandatory fields [intance, token] not found in request body');
                } else {
                    await insMgr.removeToken(tokenEx.token, parsedBody['instance'], parsedBody['token']);
                    response = comm.validResponse("token ID deleted");
                }
                break;
            }
            case "POST:/db/instance/token/revoke": {
                if (!(parsedBody != null && 'instance' in parsedBody && 'token' in parsedBody)) {
                    response = comm.errorResponse(400, 'mandatory fields [intance, token] not found in request body');
                } else {
                    await insMgr.revokeToken(tokenEx.token, parsedBody['instance'], parsedBody['token']);
                    response = comm.validResponse("token ID revoked");
                }
                break;
            }
        }
        if (response != null) {
            let toExpire = await insMgr.checkToken(tokenEx.token);
            if (toExpire != null && toExpire.seconds < configValues['SESSGUARD']) {
                let newSessToken = await insMgr.newToken(toExpire.sub, configValues['SESSTOUT'] as number);
                if (response.headers === undefined) {
                    response.headers = {};
                }
                response.headers["Set-Cookie"] = `${configValues['COOKIENAME']}=${newSessToken}; Max-Age=${configValues['SESSTOUT']}; Path=/`
            }
            return response;
        } else {
            return comm.errorResponse(400, 'path or method not implemented');
        }
    } catch (e) {
        console.log("ERROR(internal): %s\n%j", e.message, e);
        return comm.errorResponse(500, e.message);
    }
}