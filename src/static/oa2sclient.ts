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

interface clientResponse {
    custId: string;
    instances: {
        [index: string]: {
            instanceId: string
            description: string;
            activated: boolean;
            region: string;
            apitok: {
                [index: string]: {
                    value: string;
                    subject: string,
                    expiration: number;
                    revoked: boolean;
                }
            };
        }
    }
}

interface apitoken {
    value: string;
    subject: string;
    expiration: number;
    revoked: boolean;
    invalid: boolean;
    uuid: string;
}

interface lsinst {
    uuid: string;
    instanceId: string
    description: string;
    activated: boolean;
    region: string;
    used: boolean;
    apitok: apitoken[];
}

interface addInstanceResponse {
    instId: string;
}

interface addInstanceRequest {
    instance: string;
    region: string;
    description: string;
}

interface simpleInstanceRequest {
    instance: string
}

interface addTokenResponse {
    id: string,
    value: string,
    expiration: number
}

interface addTokenRequest {
    instance: string;
    maxage: number;
    subject: string;
}

interface delTokenRequest {
    instance: string,
    token: string
}

interface apiResponse<T> {
    result: string;
    message: string;
    response: T;
}

interface apiError {
    result: string;
    message: string;
}

class oa2sc {
    url: string;
    custId: string;
    instances: lsinst[];

    private constructor(url: string, cData: clientResponse) {
        this.url = url;
        this.custId = cData.custId;
        this.load(cData);
    }

    private load(response: clientResponse) {
        this.instances = [];
        for (let a of Object.keys(response.instances)) {
            let inst = response.instances[a];
            let newIns: lsinst = {
                activated: inst.activated,
                apitok: [],
                description: inst.description,
                instanceId: inst.instanceId,
                region: inst.region,
                uuid: a,
                used: false
            }
            for (let b of Object.keys(inst.apitok)) {
                let tok = inst.apitok[b];
                let newTok: apitoken = {
                    expiration: tok.expiration,
                    revoked: tok.revoked,
                    subject: tok.subject,
                    value: tok.value,
                    uuid: b,
                    invalid: tok.revoked || Math.floor(Date.now() / 1000) > tok.expiration
                }
                newIns.apitok.push(newTok);
                newIns.used = !newTok.invalid || newIns.used;
            }
            this.instances.push(newIns);
        }
    }

    static async getOa2sc(url: string): Promise<oa2sc | null> {
        let vars: { [index: string]: string } = {};
        let hash: string[] = [];
        let q = window.location.search.split('?')[1];
        if (q != undefined) {
            let p: string[] = q.split('&');
            for (let i in p) {
                hash = p[i].split('=');
                vars[hash[0]] = decodeURIComponent(hash[1]);
            }
        }
        if ('cmd' in vars && vars['cmd'] == 'create' && ['instance_id', 'region', 'description'].every(v => v in vars)) {
            try {
                await oa2sc.addInstanceInternal(
                    vars['instance_id'],
                    vars['region'],
                    vars['description'],
                    url);
            } finally {
                window.location.href = window.location.href.split('?')[0];
                return null
            };
        }
        let resp = await oa2sc.jsonReq<clientResponse>('GET', url + 'db');
        return new oa2sc(url, resp.response);
    }

    private static jsonReq<T>(method: string, uri: string, data?: object): Promise<apiResponse<T>> {
        return new Promise<apiResponse<T>>((resolve, reject) => {
            let dataObj: JQueryAjaxSettings = {
                url: uri,
                type: method
            }
            if (data != undefined) {
                dataObj['data'] = JSON.stringify(data);
                dataObj['contentType'] = "application/json; charset=utf-8";
            }
            $.ajax(dataObj).done(data => {
                resolve(data);
            }).fail(err => {
                reject(err);
            });
        });
    }

    private static async addInstanceInternal(inst: string, reg: string, desc: string, baseUrl: string): Promise<addInstanceResponse> {
        let instReq: addInstanceRequest = {
            instance: inst,
            description: desc,
            region: reg
        }
        let resp = await oa2sc.jsonReq<addInstanceResponse>('POST', baseUrl + 'db/instance', instReq);
        return resp.response;
    }

    /**
     * Normal workflow is for the instance to be created on the server side as part of the "/callback" redirection for
     * already logged in users. For non logged in users the expected workflow is for the instance to be created by the
     * {@link getOa2sc} factory. So no need to use this method ever.
     */
    async addInstance(inst: string, reg: string, desc: string): Promise<string> {
        let resp = await oa2sc.addInstanceInternal(inst, reg, desc, this.url);
        this.instances.push({
            activated: false,
            apitok: [],
            description: desc,
            instanceId: inst,
            region: reg,
            uuid: resp.instId,
            used: false
        });
        return resp.instId;
    }

    async removeInstance(instIdx: number): Promise<void> {
        let reqObj: simpleInstanceRequest = { instance: this.instances[instIdx].uuid };
        await oa2sc.jsonReq<void>('DELETE', this.url + 'db/instance', reqObj);
        this.instances.splice(instIdx, 1);
    }

    async addToken(instIdx: number, subj: string, maxa: number): Promise<string> {
        let tokenReq: addTokenRequest = {
            instance: this.instances[instIdx].uuid,
            maxage: maxa,
            subject: subj
        }
        let resp = await oa2sc.jsonReq<addTokenResponse>('POST', this.url + 'db/instance/token', tokenReq);
        this.instances[instIdx].apitok.push({
            expiration: resp.response.expiration,
            revoked: false,
            subject: subj,
            uuid: resp.response.id,
            value: resp.response.value,
            invalid: false
        });
        this.instances[instIdx].used = true;
        return resp.response.id;
    }

    async removeToken(instIdx: number, tokenIdx: number): Promise<void> {
        let reqObj: delTokenRequest = {
            instance: this.instances[instIdx].uuid,
            token: this.instances[instIdx].apitok[tokenIdx].uuid
        };
        await oa2sc.jsonReq<void>('DELETE', this.url + 'db/instance/token', reqObj);
        this.instances[instIdx].apitok.splice(tokenIdx, 1);
        this.instances[instIdx].used = this.instances[instIdx].apitok.every(t => !t.invalid);
    }

    async revokeToken(instIdx: number, tokenIdx: number): Promise<void> {
        let reqObj: delTokenRequest = {
            instance: this.instances[instIdx].uuid,
            token: this.instances[instIdx].apitok[tokenIdx].uuid
        };
        await oa2sc.jsonReq<void>('POST', this.url + 'db/instance/token/revoke', reqObj);
        this.instances[instIdx].apitok[tokenIdx].revoked = true;
        this.instances[instIdx].used = this.instances[instIdx].apitok.every(t => !t.invalid);
    }
}
