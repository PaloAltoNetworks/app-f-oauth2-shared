import { readFile } from "fs";

const STATICDIR = 'static/';
const FILES: string[] = [
    "loginpage.html",
    "apppage.html",
    "loginsrv.js",
    "oa2sclient.js",
    "appvue.js"
];

export let stContent: { [index: string]: string } = {};

function fsProcReadFile(filename: string): Promise<string> {
    return new Promise((resolve, reject) => {
        readFile(`${STATICDIR}/${filename}`, (err, data) => {
            if (err) {
                reject(err);
            } else {
                resolve(data.toString());
            }
        })
    })
}

export async function init(): Promise<void> {
    for (let item of FILES) {
        stContent[item] = await fsProcReadFile(item);
    }
}