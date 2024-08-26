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
        clientId: process.env["CLIENT_ID"],
        clientSecret: process.env["CLIENT_SECRET"],
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
    qrcode.setErrorLevel('Q');
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
    console.log("Device authorization successful");

    /*
    try {

        if (resp.access_token) {

            // No MFA - got access token
            printTokens(resp);
            process.exit(0);

        } else if (resp.error == "mfa_required" && resp.mfa_token) {

            // MFA needed
            const mfa_token = resp.mfa_token;
            resp = await oauthClient.mfaAuthenticators(mfa_token);
            if (resp.error) throw resp;
            const auth = resp.authenticators[0];

            if (auth.authenticator_type == "otp") {

                // OTP authenticator
                resp = await oauthClient.mfaOtpRequest(mfa_token, auth.id);
                if (resp.error) throw resp;

                const otp = await read({
                    prompt: "Code from Google Authenticator: ",
                });

                resp = await oauthClient.mfaOtpComplete(mfa_token, otp);
                if (resp.error) throw resp;
                printTokens(resp);
                process.exit(0);

            } else if (auth.authenticator_type == "oob") {

                // OOB authenticator
                resp = await oauthClient.mfaOobRequest(mfa_token, auth.id);
                if (resp.error) throw resp;
                if (resp.challenge_type != "oob" ||
                    !resp.oob_code || resp.binding_method != "prompt") {
                    throw {
                        error: "invalid_request",
                        error_description: "Unexpected challenge response"
                    }
                }
                const oob_code = resp.oob_code;

                const otp = await read({
                    prompt: "Enter code from email: ",
                });
                resp = await oauthClient.mfaOobComplete(mfa_token, oob_code, otp);
                if (resp.error) throw resp;
                printTokens(resp);
                process.exit(0);


            } else { 
                throw {
                    error: "invalid_request",
                    error_description: "Unsupported MFA type " + auth.authenticator_type,
                }
            }
        } else {
            throw resp;
        }
    } catch (e) {
        const resp = e as {error: string, error_description: string};
        console.log(resp.error + ": " + resp.error_description);
        process.exit(1);
    }*/

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

