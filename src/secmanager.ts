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

import { SecretsManager as SM } from 'aws-sdk';

let smClient: SM;

export function init(awsRegion: string) {
    smClient = new SM({ region: awsRegion });
}

export function smPromGetSecretValue<T>(secretName: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        smClient.getSecretValue({ SecretId: secretName }, (err, data) => {
            if (err) {
                reject(Error(err.message));
            } else {
                if (data.SecretString != undefined) {
                    try {
                        let dataObj = JSON.parse(data.SecretString);
                        resolve(dataObj as T);
                        return;
                    }
                    catch (err) {
                        reject(Error(err.message));
                        return;
                    }
                } else {
                    reject(new Error("Non-string secret value in " + secretName));
                }
            }
        })
    })
}

export function smPromUpdateSecretValue<T>(secretName: string, secretValue: T): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        smClient.putSecretValue({
            SecretId: secretName,
            SecretString: JSON.stringify(secretValue)
        }, (err, data) => {
            if (err) {
                reject(Error(err.message));
            } else {
                resolve();
            }
        })
    })
}

export function smPromDeleteSecret(secretName: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        smClient.deleteSecret({
            SecretId: secretName
        }, (err, data) => {
            if (err) {
                reject(Error(err.message));
            } else {
                resolve();
            }
        });
    })
}

export function smPromCreateSecret<T>(secretName: string, secretValue: T, description: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        smClient.createSecret({
            Name: secretName,
            SecretString: JSON.stringify(secretValue),
            Description: description
        }, (err, data) => {
            if (err) {
                reject(Error(err.code));
            } else {
                resolve();
            }
        });
    })
}
