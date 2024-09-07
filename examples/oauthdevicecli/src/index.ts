// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { OAuthClientBackend } from '@crossauth/backend';
import { read } from 'read';
import qrcode from 'qrcode-terminal';

import {
  CrossauthLogger,
  CrossauthError,
  ErrorCode,
  OAuthFlows,
  type UserInputFields } from '@crossauth/common';

async function main() {

    CrossauthLogger.logger.level = CrossauthLogger.None;

    const oauthClient = new OAuthClientBackend(
        process.env["AUTH_SERVER_BASE_URL"], { 
        client_id: process.env["CLIENT_ID"],
        client_secret: process.env["CLIENT_SECRET"],
    });
    const deviceAuthorizationUrl = process.env["DEVICE_AUTHORIZATION_URL"];

    await read({
        prompt: "Press ENTER to authorize this app to access your account: ",
    });

    let resp = await oauthClient.startDeviceCodeFlow(deviceAuthorizationUrl);

    if (resp.error) {
        console.log("Error: " + resp.error_description ?? resp.error);
        process.exit(1);
    }
    console.log("Please visit the URL " + resp.verification_uri);
    console.log("Enter the following code when prompted: " + resp.user_code);
    console.log("");
    console.log("Alternatively, scan the following QR code:");
    qrcode.setErrorLevel('L');
    qrcode.generate(resp.verification_uri_complete);
    console.log("");

    let success = false;
    const deviceCode = resp.device_code;
    while (!success) {
        resp = await oauthClient.pollDeviceCodeFlow(deviceCode);
        if (resp.error == "expired_token") {
            console.log("Code has expired:");
            process.exit(1);
        } else if (resp.error == "authorization_pending") {
            let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
            await wait((resp.interval ?? 5)*1000);
        } else if (resp.error) {
            console.log("Error waiting for authorization: " + (resp.error_desciption ?? resp.error));
            process.exit(1);
        } else {
            success = true;
        }
    }
    console.log("");
    console.log("Device authorization successful");
    console.log("");


    if (resp.access_token) {
        printTokens(resp);
    } 

}

function printTokens(resp : {[key:string]:any}) {
    console.log("access_token", resp.access_token);
    if (resp.refresh_token) console.log("refresh_token", resp.refresh_token);
    if (resp.id_token) console.log("refresh_token", resp.id_token);
}

main()
  .then(async () => {
  })
  .catch(async (e) => {
    console.error(e);
    process.exit(1)
  })
