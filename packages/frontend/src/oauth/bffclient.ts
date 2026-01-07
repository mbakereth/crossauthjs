// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { CrossauthError, CrossauthLogger, j } from "@crossauth/common";
import { OAuthAutoRefresher } from './autorefresher.ts';
import { OAuthDeviceCodePoller } from './devicecodepoller.ts';

/**
 * A browser-side OAuth client designed with work with the
 * backend-for-frontend (BFF) mode of the backend OAuth client.
 * 
 * You may use this, or alternatively the backend OAuth clients, eg
 * 
 * `@crossauth/fastify/FastifyOAuthClient` or
 * .`@crossauth/sveltekit/SvelteKitOAuthClient`
 */
export class OAuthBffClient {
    private bffPrefix : string = "/bff";
    private csrfHeader : string = "X-CROSSAUTH-CSRF";
    private enableCsrfProtection: boolean = true;
    private headers : {[key:string]:string} = {};
    private mode :  "no-cors" | "cors" | "same-origin" = "cors";
    private credentials : "include" | "omit" | "same-origin" = "same-origin";
    private autoRefresher : OAuthAutoRefresher;
    private deviceCodePoller : OAuthDeviceCodePoller;
    private getCsrfTokenUrl = "/api/getcsrftoken";
    private autoRefreshUrl = "/api/refreshtokens";
    private tokensUrl = "/tokens";

    /**
     * Constructor
     * 
     * @param options
     *   - `bffPrefix` the base url for BFF calls to the OAuth client
     *        (eg `bff`, which is the default)
     *   - `csrfHeader` the header to put CSRF tokens into 
     *        (default `X-CROSSAUTH-CSRF`))
     *   - `getCsrfTokenUrl` URL to use to fetch CSRF tokens.  Default is
     *        `/api/getcsrftoken`
     *   - `autoRefreshUrl` URL to use to refresh tokens.  Default is
     *        `/api/refreshtokens`
     *   - `tokensUrl` URL to use to fetch token payloads.  Default is
     *        `/tokens`
     *   - `deviceCodePollUrl` URL for polling for device code authorization.  
     *      Default is `/devicecodepoll`
     *   - `mode` overrides the default `mode` in fetch calls
     *   - `credentials` - overrides the default `credentials` for fetch calls
     *   - `headers` - adds headers to fetfh calls
     */
    constructor(options : {
            bffPrefix? : string,
            csrfHeader? : string,
            credentials? : "include" | "omit" | "same-origin",
            mode? : "no-cors" | "cors" | "same-origin",
            headers? : {[key:string]:any},
            enableCsrfProtection? : boolean,
            getCsrfTokenUrl? : string,
            autoRefreshUrl? : string,
            tokensUrl? : string,
            deviceCodePollUrl? : string,

        } = {}) {
        if (options.bffPrefix) this.bffPrefix = options.bffPrefix;
        if (options.csrfHeader) this.csrfHeader = options.csrfHeader;
        if (options.enableCsrfProtection != undefined) this.enableCsrfProtection = options.enableCsrfProtection;
        if (options.getCsrfTokenUrl) this.getCsrfTokenUrl = options.getCsrfTokenUrl;
        if (options.tokensUrl) this.tokensUrl = options.tokensUrl;
        if (options.autoRefreshUrl) this.autoRefreshUrl = options.autoRefreshUrl;
        /*if (this.bffPrefix.startsWith("/") && this.bffPrefix.length > 1) {
            this.bffPrefix = this.bffPrefix.substring(1);
        }*/
        if (!(this.bffPrefix.endsWith("/"))) this.bffPrefix += "/";
        if (options.headers) this.headers = options.headers;
        if (options.mode) this.mode = options.mode;
        if (options.credentials) this.credentials = options.credentials;

        this.autoRefresher = new OAuthAutoRefresher({
            ...options,
            autoRefreshUrl: this.autoRefreshUrl,
            tokenProvider: this,
        });

        this.deviceCodePoller = new OAuthDeviceCodePoller({...options, oauthClient: undefined});
    }

    /**
     * Gets a CSRF token from the server
     * @returns the CSRF token that can be included in
     *          the `X-CROSSAUTH-CSRF` header
     */
    async getCsrfToken() : Promise<string|undefined> {
        if (!this.enableCsrfProtection) return undefined;
        try {
            const resp = await fetch(this.getCsrfTokenUrl, {
                headers: this.headers,
                credentials: this.credentials,
                mode: this.mode,
            });
            const json = await resp.json();
            if (!json.ok) throw CrossauthError.asCrossauthError(json);
            return json.csrfToken;
        } catch (e) {
            throw CrossauthError.asCrossauthError(e);
        }
    }

    /**
     * Fetches the ID token from the client.
     * 
     * This only returns something if the ID token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns the ID token payload or an empty object if there isn't one
     */
    async getIdToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        const tokens = await this.getTokens(csrfToken);
        return tokens?.id_token ?? null;
    }

    /**
     * Returns whether or not there is an ID token stored in the BFF server
     * for this client.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveIdToken(csrfToken? : string) : Promise<boolean>{
        const tokens = await this.getTokens(csrfToken);
        if (tokens == null) return false;
        if (tokens.have_id_token != undefined) return tokens.have_id_token
        return "id_token" in tokens;
    }

    /**
     * Fetches the access token from the client.
     * 
     * This only returns something if the access token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns the access token payload or an empty object if there isn't one
     */
    async getAccessToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        const tokens = await this.getTokens(csrfToken);
        return tokens?.access_token ?? null;
    }

    /**
     * Returns whether or not there is an access token stored in the BFF server
     * for this client.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveAccessToken(csrfToken? : string) : Promise<boolean>{
        const tokens = await this.getTokens(csrfToken);
        if (tokens == null) return false;
        if (tokens.have_access_token != undefined) return tokens.have_access_token
        return "access_token" in tokens;
    }

    /**
     * Fetches the refresh token from the client.
     * 
     * This only returns something if the refresh token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns the refresh token payload or an empty object if there isn't one
     */
    async getRefreshToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        const tokens = await this.getTokens(csrfToken);
        return tokens?.refresh_token ?? null;
    }

    /**
     * Returns whether or not there is a refresh token stored in the BFF server
     * for this client.
     * 
     * @param csrfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveRefreshToken(csrfToken? : string) : Promise<boolean>{
        const tokens = await this.getTokens(csrfToken);
        if (tokens == null) return false;
        if (tokens.have_refresh_token != undefined) return tokens.have_refresh_token
        return "refresh_token" in tokens;
    }

    /**
     * Calls an API endpoint via the BFF server
     * @param method the HTTP method 
     * @param endpoint the endpoint to call, relative to `bffPrefix` 
     * @param body : the body to pass to the call
     * @param csrfToken : the CSRF token
     * @returns the HTTP status code and the body or null
     */
    async api(method : "GET"|"POST"|"PUT"|"PATCH"|"OPTIONS"|"HEAD"|"DELETE",
        endpoint : string,
        body? : {[key:string]:any}, 
        csrfToken? : string) : 
        Promise<{status : number, body : {[key:string]:any}|null}> {
        let headers = {...this.headers};
        if (!csrfToken && !(["GET", "HEAD", "OPTIONS"].includes(method))) {
            csrfToken = await this.getCsrfToken();
            if (csrfToken) headers[this.csrfHeader] = csrfToken;
        }
        if (endpoint.startsWith("/")) endpoint = endpoint.substring(1);
        let params : {body? : string}= {};
        if (body) params.body = JSON.stringify(body);
        const resp = await fetch(this.bffPrefix + endpoint, 
            {
                headers: headers,
                method: method,
                mode: this.mode,
                credentials: this.credentials,
                ...params,
            });
        let responseBody : {[key:string]:any} | null = null;
        if (resp.body) responseBody = await resp.json();
        return {status: resp.status, body: responseBody};
    }

    /**
     * Return all tokens that the client has been enabled to return.
     * 
     * @param csrfToken the CSRF token if one is needed
     * @returns an object with the following (whichever are enabled at the client)
     *   - `id_token`
     *   - `access_token`
     *   - `refresh_token`
     *   - `have_id_token`
     *   - `have_access_token`
     *   - `have_refresh_token`
     */
    async getTokens(csrfToken? : string,) : Promise<{[key:string]:any}|null>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        let headers = {...this.headers};
        if (csrfToken)
            headers[this.csrfHeader] = csrfToken;
        try {
            const resp = await fetch(this.tokensUrl, {
                method: "POST",
                headers: headers,
                mode: this.mode,
                credentials: this.credentials,
            })
            if (resp.status == 204) {
                return {};
            }
            const body = await resp.json();
            return body;
            //return await resp.json();
        } catch (e) {
            throw CrossauthError.asCrossauthError(e);
        }
    }

    /**
     * Turns auto refresh of tokens on
     * @param tokensToFetch which tokens to fetch
     * @param errorFn what to call in case of error
     */
    async startAutoRefresh(tokensToFetch : ("access"|"id")[] = ["access", "id"], 
        errorFn? : (msg : string, e? : CrossauthError) => void) {
    
        return this.autoRefresher.startAutoRefresh(tokensToFetch, errorFn);
    }


    /**
     * Turns auto refresh of tokens off
     */
    stopAutoRefresh() {
        return this.autoRefresher.stopAutoRefresh();
    }

    /**
     * Turns polling for a device code
     * @param deviceCode the device code to poll for (returned when the device code flow was started)
     * @param pollResultFn THis function will be called with the result of each poll
     */
    async startDeviceCodePolling(deviceCode : string, 
        pollResultFn : (status: ("complete"|"completeAndRedirect"|"authorization_pending"|"expired_token"|"error"), error? : string, location? : string) => void, interval : number = 5) {
    
        return this.deviceCodePoller.startPolling(deviceCode, pollResultFn, interval);
    }


    /**
     * Turns off polling for a device code
     */
    stopDeviceCodePolling() {
        return this.deviceCodePoller.stopPolling();
    }
    
    ///////////////////////////////////////////////////////////
    // OAuthTokenProvider interface

    /**
     * Fetches the expiry times for each token.
     * @param csrfToken the CSRF token.  If emtpy
     * , one will be fetched before
     *        making the request
     * @returns for each token, either the expiry, `null` if it does not
     *          expire, or `undefined` if the token does not exist
     */
    async getTokenExpiries(tokensToFetch : ("access"|"id"|"refresh")[], 
        csrfToken? : string) : 
        Promise<{
            id: number | null | undefined,
            access: number | null | undefined,
            refresh: number | null | undefined
        }> {

            // Get tokens
            const tokens = await this.getTokens(csrfToken);
                try {
                const idToken = tokensToFetch.includes("id") ? tokens?.id_token ?? null : null;
                const accessToken = tokensToFetch.includes("access") ? tokens?.access_token ?? null : null;
                const refreshToken = tokensToFetch.includes("refresh") ? tokens?.refresh_token ?? null : null;

                // get expiries
                let idTokenExpiry : number | null | undefined = undefined;
                let accessTokenExpiry : number | null | undefined = undefined;
                let refreshTokenExpiry : number | null | undefined = undefined;
                if (idToken) {
                    idTokenExpiry = idToken.exp ? idToken.exp : null;
                }
                if (accessToken) {
                    accessTokenExpiry = accessToken.exp ? accessToken.exp : null;
                }
                if (refreshToken) {
                    refreshTokenExpiry = refreshToken.exp ? refreshToken.exp : null;
                }
                
                return {
                    id : idTokenExpiry,
                    access : accessTokenExpiry,
                    refresh : refreshTokenExpiry
                };
            } catch (e) {
                CrossauthLogger.logger.error(j({msg: "getTokenExpiries received non JSON response " + tokens}))
                return {
                    id : 0,
                    access : 0,
                    refresh : 0
                };
            }
        }

    /**
     * Makes a fetch, adding in the requested token
     * @param url the URL to fetch
     * @param params parameters to add to the fetch
     * @param _token unused
     * @returns parsed JSON response
     */
    async jsonFetchWithToken(url: string,
        params: {[key:string]:any},
        _token: "access" | "refresh") :
        Promise<Response> {
            
            if (typeof params.body != "string") params.body = JSON.stringify(params.body);
            return await fetch(url, params);
        }

    receiveTokens(_tokens : {
        access_token? : string|null,
        id_token? : string|null,
        refresh_token? : string|null
    }) : Promise<void> {
        return new Promise(_resolve => {});
    }
}
