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

import { DynamoDB } from 'aws-sdk';

export const DBERROREMPTY = 'invalid data';

interface dbi {
    id: string
}

let docuClient: DynamoDB.DocumentClient;
let tableName: string;

export function init(awsRegion: string, table: string): void {
    docuClient = new DynamoDB.DocumentClient({ region: awsRegion });
    tableName = table;
}

export function putItem<T extends dbi>(prefix: string, item: T): Promise<void> {
    item.id = `${prefix}#${item.id}`;
    return new Promise<void>((resolve, reject) => docuClient.put({
        TableName: tableName,
        Item: item
    }, (err, data) => {
        if (err != null) {
            reject(Error(err.message));
        } else {
            resolve();
        }
    }));
}

export function getItem<T extends dbi>(prefix: string, id: string): Promise<T> {
    return new Promise<T>((resolve, reject) => docuClient.get({
        TableName: tableName,
        Key: {
            id: `${prefix}#${id}`
        }
    }, (err, data) => {
        if (err != null) {
            reject(Error(err.message));
        } else if (data == null || !("Item" in data)) {
            reject(Error(DBERROREMPTY));
        } else {
            let returnData: T = data.Item as T;
            returnData.id = returnData.id.substr(prefix.length + 1);
            resolve(returnData);
        }
    }))
}

export async function getSafeItem<T extends dbi>(prefix: string, id: string, def: T): Promise<T> {
    let value: T;
    try {
        value = await getItem<T>(prefix, id);
    } catch (e) {
        if (e.message == DBERROREMPTY) {
            return def;
        }
        throw e;
    }
    return value;
}
