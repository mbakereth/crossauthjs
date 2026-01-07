// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { OAuthClientBase, CrossauthError, CrossauthLogger, j } from "@crossauth/common";

/**
 * Used by {@link OAuthClient} and {@link OAuthBffClient} to poll for 
 * authorization in the device code flow
 */
export class OAuthDeviceCodePoller {
    private deviceCodePollUrl : string|null = "/devicecodepoll";
    protected headers : {[key:string]:string} = {};
    private pollingActive = false;
    protected mode :  "no-cors" | "cors" | "same-origin" = "cors";
    protected credentials : "include" | "omit" | "same-origin" = "same-origin";
    protected respectRedirect = true;
    protected oauthClient? : OAuthClientBase;

    /**
     * Constructor
     * 
     * @param options
     *   - `deviceCodePollUrl` the URL to call to poll for authorization.  Default `/devicecodepoll`
     *   - `mode` overrides the default `mode` in fetch calls
     *   - `credentials` - overrides the default `credentials` for fetch calls
     *   - `headers` - adds headers to fetfh calls
     */
    constructor(options  : {
        deviceCodePollUrl? : string|null,
        credentials? : "include" | "omit" | "same-origin",
        mode? : "no-cors" | "cors" | "same-origin",
        headers? : {[key:string]:any},
        oauthClient? : OAuthClientBase,
    
    }) {
    this.oauthClient = options.oauthClient;
    if (options.deviceCodePollUrl != undefined) this.deviceCodePollUrl = options.deviceCodePollUrl;
    if (options.headers) this.headers = options.headers;
    if (options.mode) this.mode = options.mode;
    if (options.credentials) this.credentials = options.credentials;
}


    async startPolling(deviceCode : string, pollResultFn : (status: ("complete"|"completeAndRedirect"|"authorization_pending"|"expired_token"|"error"), error? : string, location? : string) => void, interval : number = 5) {

        if (!this.pollingActive) {
            this.pollingActive = true;
            CrossauthLogger.logger.debug(j({msg: "Starting auto refresh"}));
            await this.poll(deviceCode, interval, pollResultFn);
        }
    }


    stopPolling() {
        this.pollingActive = false;
        CrossauthLogger.logger.debug(j({msg: "Stopping auto refresh"}));
    }

    private async poll(deviceCode: string, interval : number, pollResultFn : (status: ("complete"|"completeAndRedirect"|"authorization_pending"|"expired_token"|"error"), error? : string, location? : string) => void) {
        if (!deviceCode) {
            CrossauthLogger.logger.debug(j({msg: "device code poll: no device code provided"}));
            pollResultFn("error",  "Error waiting for authorization");
        } else {
            try {
                CrossauthLogger.logger.debug(j({msg: "device code poll: poll"}));
                if (!this.deviceCodePollUrl && this.oauthClient) {
                    if (!this.oauthClient.getOidcConfig()) await this.oauthClient.loadConfig();
                    if (!this.oauthClient.getOidcConfig()?.grant_types_supported
                        .includes("http://auth0.com/oauth/grant-type/mfa-oob")) {
                        return {
                            error: "invalid_request",
                            error_description: "Server does not support password_mfa grant"
                        };
                    }
            
                    let config = this.oauthClient.getOidcConfig();
                    if (!config?.token_endpoint) return {
                        error: "server_error",
                        error_description: "Couldn't get OIDC configuration"
                    };
                    this.deviceCodePollUrl = config.token_endpoint;
            
                }
                if (!this.deviceCodePollUrl) {
                    return {
                        error: "server_error",
                        error_description: "Must either provide deviceCodePollUrl or an oauthClient to fetch it from",
                    }
                }
                const resp = await fetch(this.deviceCodePollUrl, {
                    method: "POST",
                    body: JSON.stringify({device_code: deviceCode}),
                    headers: {"content-type": "application/json"}
                });
                if (resp.redirected) {
                    // in the event our token receive function does a redirect
                    this.pollingActive = false;
                    if (resp.redirected) {
                        pollResultFn("completeAndRedirect",  undefined, resp.url);
                    }
                } else if (!resp.ok) {
                    this.pollingActive = false;
                    pollResultFn("error",  "Received an error from the authorization server");
                } else {
                    const body = await resp.json();
                    CrossauthLogger.logger.debug(j({msg:"device code poll: received"+JSON.stringify(body)}));
                    if (body.error == "expired_token") {
                        this.pollingActive = false;
                        pollResultFn("expired_token", "Timeout waiting for authorization");
                    } else if (body.error == "authorization_pending" || body.error == "slow_down") {
                        if (body.error == "slow_down") interval += 5;
                        let waitseconds = (body.interval ?? interval);
                        let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
                        CrossauthLogger.logger.debug(j({msg:"device code poll: waiting " + String(waitseconds)+ " seconds"}))
                        await wait(waitseconds*1000);
                        if (this.pollingActive) this.poll(deviceCode, interval, pollResultFn);
                    } else if (body.error) {
                        this.pollingActive = false;
                        pollResultFn("error", body.error_description ?? body.error);
                    } else {
                        //if (resp.redirected) goto(resp.url);
                        this.pollingActive = false;
                        pollResultFn("complete");
                    }
                }
            } catch (e) {
                this.pollingActive = false;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({msg: "Polling failed", cerr: ce}));
                pollResultFn("error", ce.message);
            }

        }
    }

}
