// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { OAuthClientBackend } from '@crossauth/backend';
import { read } from 'read';

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

    const username = await read({
        prompt: "Username: ",
    });
    const password = await read({
        prompt: "Password: ",
        silent: true,
        replace: "*" 
    });

    let resp = await oauthClient.passwordFlow(username, password, "read write");

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
