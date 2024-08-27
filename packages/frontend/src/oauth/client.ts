//import { URLSearchParams } from "url";
import {
    OAuthClientBase,
    CrossauthLogger,
    j,
    ErrorCode,
    CrossauthError } from '@crossauth/common'
import type { OAuthTokenResponse, OAuthDeviceAuthorizationResponse } from '@crossauth/common'
import { OAuthAutoRefresher } from './autorefresher.ts';
import { OAuthDeviceCodePoller } from './devicecodepoller.ts';
import { OAuthTokenConsumer } from './tokenconsumer';
/**
 * This is the type for a function that is called when an OAuth endpoint
 * returns the `error` field.
 */
export type ErrorFn = (client : OAuthClient,
    error : string,
    errorDescription? : string) => Promise<any>;

/**
 * If this URL was called with an OAuth authorize response, the `token`
 * endpoint will be called and, if successful, passed to this function.
 */
export type ReceiveTokenFn = (client : OAuthClient,
    response : OAuthTokenResponse) => Promise<any>;
    
export type TokenResponseType = 
    "memory" |
    "localStorage" |
    "sessionStorage";

export class OAuthClient extends OAuthClientBase {
    private resServerBaseUrl : string = "";
    private resServerHeaders : {[key:string]:string} = {};
    private resServerMode :  "no-cors" | "cors" | "same-origin" = "cors";
    private resServerCredentials : "include" | "omit" | "same-origin" = "same-origin";
    private accessTokenResponseType? : TokenResponseType = "memory";
    private refreshTokenResponseType? : TokenResponseType = "memory";
    private idTokenResponseType? : TokenResponseType = "memory";
    private accessTokenName : string = "CROSSAUTH_AT";
    private refreshTokenName : string = "CROSSAUTH_RT";
    private idTokenName : string = "CROSSAUTH_IT";
    #accessToken : string | undefined;
    #refreshToken : string | undefined;
    #idTokenPayload : {[key:string]:any} | undefined;
    get idTokenPayload() {return this.#idTokenPayload;}
    #accessTokenPayload : {[key:string]:any} | undefined;
    #refreshTokenPayload : {[key:string]:any} | undefined;
    #clientId : string|undefined;
    #clientSecret : string|undefined;
    private autoRefresher : OAuthAutoRefresher;
    private deviceCodePoller : OAuthDeviceCodePoller;
    private deviceAuthorizationUrl = "device_authorization";

    /**
     * Constructor
     * 
     * @param options
     *   - `authServerBaseUrl` the base url the authorization server.
     *      For example, the authorize endpoint would be
     *      `authServerBaseUrl + "authorize"`.
     *       Required: no default
     *   - `resServerBaseUrl` the base url the resource server.
     *      For example, Relative URLs to the resource server are relative
     *      to this.  If you always give absolute URLs, this is optional.
     *      If you don't give it and you do make relative URLs, it will be
     *      relative to the page you are on.  Default: empty string.
     *   - `redirectUri` a URL on the site serving this app which the
     *      authorization server will redirect to with an authorization
     *      code.  See description in class documentation.
     *      This is not required if you are not using OAuth flows
     *      which require a redirect URI (eg the password flow).
     *   - `accessTokenResponseType` where to store access tokens.  See
     *     class documentation.  Default `return`.
     *   - `refreshTokenResponseType` where to store refresh tokens.  See
     *     class documentation.  Default `return`.
     *   - `idTokenResponseType` where to store id tokens.  See
     *     class documentation.  Default `return`.
     *   - `accessTokenName` name for access token in local or session
     *     storage, depending on `accessTokenResponseType`
     *   - `refreshTokenName` name for refresh token in local or session
     *     storage, depending on `refreshTokenResponseType`
     *   - `idTokenName` name for id token in local or session
     *     storage, depending on `idTokenResponseType`
     *   - `mresServerMode` overrides the default `mode` in fetch calls
     *   - `resServerCredentials` - overrides the default `credentials` for fetch calls
     *   - `resServerHeaders` - adds headers to fetfh calls
     *   - `autoRefresh` - if set and tokens are present in local or session storage, 
     *      automatically turn on auto refresh
     *   - `deviceAuthorization` URL, relative to the authorization server base, 
     *      for starting the device code flow.  Default `device_authorization`
     *      Default is `/devicecodepoll`
     *  For other options see {@link @crossauth/common/OAuthClientBase}.
     */
    constructor(options  : {
            authServerBaseUrl : string,
            stateLength? : number,
            verifierLength? : number,
            clientId : string,
            clientSecret? : string,
            redirectUri? : string,
            codeChallengeMethod? : "plain" | "S256",
            tokenConsumer : OAuthTokenConsumer,
            resServerBaseUrl? : string,
            accessTokenResponseType? : TokenResponseType,
            refreshTokenResponseType? : TokenResponseType,
            idTokenResponseType? : TokenResponseType,
            accessTokenName? : string,
            refreshTokenName? : string,
            idTokenName? : string,
            resServerCredentials? : "include" | "omit" | "same-origin",
            resServerMode? : "no-cors" | "cors" | "same-origin",
            resServerHeaders? : {[key:string]:any},
            autoRefresh? : ("access"|"id")[]
            deviceAuthorizationUrl? : string,
        }) {
        if (!options.tokenConsumer) {
            options.tokenConsumer = new OAuthTokenConsumer(
                options.clientId, 
                {authServerBaseUrl: options.authServerBaseUrl, 
            });
        }
        super(options);
        if (this.resServerBaseUrl != undefined) {
            this.resServerBaseUrl = options.resServerBaseUrl ?? "";
            if (this.resServerBaseUrl.length > 0 && 
                !(this.resServerBaseUrl.endsWith("/"))) {
                    this.resServerBaseUrl += "/";
                }
        }
        if (options.accessTokenResponseType) this.accessTokenResponseType = options.accessTokenResponseType;
        if (options.idTokenResponseType) this.idTokenResponseType = options.idTokenResponseType;
        if (options.refreshTokenResponseType) this.refreshTokenResponseType = options.refreshTokenResponseType;
        if (options.accessTokenName) this.accessTokenName = options.accessTokenName;
        if (options.idTokenName) this.idTokenName = options.idTokenName;
        if (options.refreshTokenName) this.refreshTokenName = options.refreshTokenName;
        if (options.resServerHeaders) this.resServerHeaders = options.resServerHeaders;
        if (options.resServerMode) this.resServerMode = options.resServerMode;
        if (options.resServerCredentials) this.resServerCredentials = options.resServerCredentials;
        if (options.clientId) this.#clientId = options.clientId;
        if (options.clientSecret) this.#clientSecret = options.clientSecret;
        if (options.deviceAuthorizationUrl) this.deviceAuthorizationUrl = options.deviceAuthorizationUrl;

        this.autoRefresher = new OAuthAutoRefresher({
            ...options,
            autoRefreshUrl: this.authServerBaseUrl + "/token",
            tokenProvider: this,
        });

        this.deviceCodePoller = new OAuthDeviceCodePoller({...options, oauthClient: this, deviceCodePollUrl: null});

        // if tokens were saved in local or session storage, fetch them.
        // turn on auto refresh if we have tokens.
        // if we didn't get tokens from session or local storage, user will
        // have to turn on auto refresh manually
        let idToken : string | null | undefined;
        let accessToken : string | null | undefined;
        let refreshToken : string | null | undefined;
        if (this.idTokenResponseType == "sessionStorage") {
            idToken = sessionStorage.getItem(this.idTokenName);
        } else if (this.idTokenResponseType == "localStorage") {
            idToken = localStorage.getItem(this.idTokenName);
        }
        if (this.accessTokenResponseType == "sessionStorage") {
            accessToken = sessionStorage.getItem(this.accessTokenName);
        } else if (this.accessTokenResponseType == "localStorage") {
            accessToken = localStorage.getItem(this.accessTokenName);
        }
        if (this.refreshTokenResponseType == "sessionStorage") {
            refreshToken = sessionStorage.getItem(this.refreshTokenName);
        } else if (this.refreshTokenResponseType == "localStorage") {
            refreshToken = localStorage.getItem(this.refreshTokenName);
        }
        this.receiveTokens({access_token: accessToken,
            id_token : idToken,
            refresh_token : refreshToken,
        })

        // get access token payload if we have the token.  This is
        // synchronous
        if (accessToken) {
            const payload = this.getTokenPayload(accessToken);
            if (payload) {
                this.#accessToken = accessToken;
                this.#accessTokenPayload = payload;
            }
        }

        // get refresh token payload if we have the token.  This is
        // synchronous
        if (refreshToken) {
            const payload = this.getTokenPayload(refreshToken);
            if (payload) {
                this.#refreshToken = refreshToken;
                this.#refreshTokenPayload = payload;
            }
        }

        // get the ID token payload if we have the token.  This is
        // asynchronous so we put the next steps in the then clause
        if (idToken) {
            this.validateIdToken(idToken)
                .then(payload => {
                // save the payload and start auto refresh, if it was requested
                this.#idTokenPayload = payload;
                if (options.autoRefresh) {
                    this.startAutoRefresh(options.autoRefresh)
                        .then()
                        .catch(err => {
                        CrossauthLogger.logger.debug(j({err: err, msg: "Couldn't start auto refresh"}));
                    });
                }
            })
            .catch(err => {
                CrossauthLogger.logger.debug(j({err: err, msg: "Couldn't validate ID token"}));
            });

        // if we don't have the ID token but we do have the access and
        // refresh tokens, and auto refresh was requested, 
        // still start auto refresh
        } else if (this.#accessToken && options.autoRefresh && refreshToken) {
            this.startAutoRefresh(options.autoRefresh)
                .then()
                .catch(err => {
                CrossauthLogger.logger.debug(j({err: err, msg: "Couldn't start auto refresh"}));
            });

        // otherwise, if we have the refresh token but neither access nor
        // ID tokens, fetch them now then start auto refresh if requested
        } else if (refreshToken && !accessToken) {
            this.refreshTokenFlow(refreshToken)
                .then(_resp => {
                    CrossauthLogger.logger.debug(j({msg: "Refreshed tokens"}));
                    if (options.autoRefresh) {
                        this.startAutoRefresh(options.autoRefresh)
                        .then()
                        .catch(err => {
                        CrossauthLogger.logger.debug(j({err: err, msg: "Couldn't start auto refresh"}));
                    });    
                }
                })
                .catch(err => {
                    const ce = CrossauthError.asCrossauthError(err);
                    CrossauthLogger.logger.debug(j({err: ce}));
                    CrossauthLogger.logger.error(j({msg: "failed refreshing tokens", cerr: ce}));
                })
        }
        
    }

    /**
     * Processes the query parameters for a Redirect URI request if they
     * exist in the URL.
     * 
     * Call this on page load to see if it was called as redirect URI.
     * 
     * If this URL doesn't match the redirect URI passed in the constructor,
     * or this URL was not called with OAuth Redirect URI query parameters,
     * undefined is returned.
     * 
     * If this URL contains the error query parameter, `errorFn` is called.
     * It is also called if the state does not match.
     * 
     * If an authorization code was in the query parameters, the token
     * endpoint is called.  Depending on whether that returned an error,
     * either `receiveTokenFn` or `errorFn` will be called.
     * 
     * @param receiveTokenFn if defined, called if a token is returned.
     *        
     * @param errorFn if defined, called if any OAuth endpoint returned `error`, 
     *        or if the `state` was not correct.
     * 
     * @returns the result of `receiveTokenFn`, `errorFn` or `undefined`.  If
     *          `receiveTokenFn`/`errorFn` is not defined, rather than calling
     *          it, this function just returns the OAuth response.
     *       
     */
    async handleRedirectUri() : Promise<any|undefined> {
        const url = new URL(window.location.href);
        if (url.origin + url.pathname != this.redirectUri) return undefined;
        const params = new URLSearchParams(window.location.search);
        let code : string|undefined = undefined;
        let state : string|undefined = undefined;
        let error : string|undefined = undefined;
        let error_description : string|undefined = undefined;
        for (const [key, value] of params) {
            if (key == "code") code = value;
            if (key == "state") state = value;
            if (key == "error") error = value;
            if (key == "error_description") error_description = value;
        }
        if (!error && !code) return undefined;

        if (error) {
            const cerr = CrossauthError.fromOAuthError(error, error_description);
            CrossauthLogger.logger.debug(j({err: cerr}));
            CrossauthLogger.logger.error(j({cerr: cerr, msg: "Error from authorize endpoint: " + error}));
            throw cerr;
        }
        const resp = await this.redirectEndpoint(code, state, error, error_description);
        if (resp.error) {
            const cerr = CrossauthError.fromOAuthError(resp.error, error_description);
            CrossauthLogger.logger.debug(j({err: cerr}));
            CrossauthLogger.logger.error(j({cerr: cerr, msg: "Error from redirect endpoint: " + resp.error}));
            throw cerr;
        }

            await this.receiveTokens(resp);
            return resp;
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
     * @param tokensToFetch which tokens to fetch
     * @param errorFn what to call in case of error
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

    /**
     * Return the ID token payload
     * 
     * This does the same thign as {@link idTokenPayload}.  We have it here
     * as well for consistency with {@link OAuthBffClient}.
     * 
     * @returns the payload as an object
     */
    getIdToken() {
        return this.#idTokenPayload;
    }


    ///////
    // Implementation of abstract methods

    /**
     * Produce a random Base64-url-encoded string, whose length before 
     * base64-url-encoding is the given length,
     * @param length the length of the random array before base64-url-encoding.
     * @returns the random value as a Base64-url-encoded srting
     */
    protected randomValue(length : number) : string {
        const array = new Uint8Array(length);
        self.crypto.getRandomValues(array);
        return btoa(array.reduce((acc, current) => acc + String.fromCharCode(current), ""))
            .replace(/\//g, "_")
            .replace(/\+/g, "-")
            .replace(/=+$/, "");
    }

    /**
     * SHA256 and Base64-url-encodes the given test
     * @param plaintext the text to encode
     * @returns the SHA256 hash, Base64-url-encode
     */
    protected async sha256(plaintext :string) : Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const hash = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hash)); 
        return btoa(hashArray.reduce((acc, current) => acc + String.fromCharCode(current), ""))
            .replace(/\//g, "_")
            .replace(/\+/g, "-")
            .replace(/=+$/, "");
    }
    
    /**
     * Calls an API endpoint on the resource server
     * @param method the HTTP method 
     * @param endpoint the endpoint to call, relative to `resServerBaseUrl` 
     * @param body : the body to pass to the call
     * @returns the HTTP status code and the body or null
     */
    async api(method : "GET"|"POST"|"PUT"|"PATCH"|"OPTIONS"|"HEAD"|"DELETE",
        endpoint : string,
        body? : {[key:string]:any}) : 
        Promise<{status : number, body : {[key:string]:any}|null}> {
        let headers = {...this.resServerHeaders};
        if (endpoint.startsWith("/")) endpoint = endpoint.substring(1);
        let params : {body? : string}= {};
        if (body) params.body = JSON.stringify(body);

        let accessToken : string | null | undefined;
        if (this.accessTokenResponseType == "sessionStorage") {
            accessToken = sessionStorage.getItem(this.accessTokenName);
        } else if (this.accessTokenResponseType == "localStorage") {
            accessToken = localStorage.getItem(this.accessTokenName);
        }
        headers.authorization = "Bearer " + accessToken;
        const resp = await fetch(this.resServerBaseUrl + endpoint, 
            {
                headers: headers,
                method: method,
                mode: this.resServerMode,
                credentials: this.resServerCredentials,
                ...params,
            });
        let responseBody : {[key:string]:any} | null = null;
        if (resp.body) responseBody = await resp.json();
        return {status: resp.status, body: responseBody};
    }

    ///////////////////////////////////////////////////////////
    // OAuthTokenProvider interface

    /**
     * Fetches the expiry times for each token.
     * @param crfToken the CSRF token.  If emtpy
     * , one will be fetched before
     *        making the request
     * @returns for each token, either the expiry, `null` if it does not
     *          expire, or `undefined` if the token does not exist
     */
    async getTokenExpiries(_tokensToFetch : ("access"|"id"|"refresh")[], 
        _csrfToken? : string) : 
        Promise<{
            id: number | null | undefined,
            access: number | null | undefined,
            refresh: number | null | undefined
        }> {

            // get expiries
            let idTokenExpiry : number | null | undefined = undefined;
            let accessTokenExpiry : number | null | undefined = undefined;
            let refreshTokenExpiry : number | null | undefined = undefined;
            if (this.#idTokenPayload) {
                idTokenExpiry = this.#idTokenPayload.exp ? this.#idTokenPayload.exp : null;
            }
            if (this.#accessTokenPayload) {
                accessTokenExpiry = this.#accessTokenPayload.exp ? this.#accessTokenPayload.exp : null;
            }
            if (this.#refreshTokenPayload) {
                refreshTokenExpiry = this.#refreshTokenPayload.exp ? this.#refreshTokenPayload.exp : null;
            }
            
            return {
                id : idTokenExpiry,
                access : accessTokenExpiry,
                refresh : refreshTokenExpiry
            };
        }

    /**
     * Makes a fetch, adding in the requested token.  
     * 
     * Also adds client ID and secret if they are defined.
     * 
     * @param url the URL to fetch
     * @param params parameters to add to the fetch
     * @param token which token to add
     * @returns parsed JSON response
     */
    async jsonFetchWithToken(url: string,
        params: {[key:string]:any},
        token: "access" | "refresh") :
        Promise<Response> {
            
            if (token == "access") {
                if (!this.#accessToken) {
                    throw new CrossauthError(ErrorCode.InvalidToken, "Cannot make fetch with access token - no access token defined");
                }
                if (!params.headers) params.headers = {};
                params.headers.authorization = "Bearer " + this.#accessToken;    
            } else {
                if (!params.body) params.body = {};
                if (!this.#refreshToken) {
                    throw new CrossauthError(ErrorCode.InvalidToken, "Cannot make fetch with refresh token - no refresh token defined");
                }
                params.body.refresh_token = this.#refreshToken;
                params.body.grant_type = "refresh_token";
            }
            if (this.#clientId) {
                if (!params.body) params.body = {};
                params.body.client_id = this.#clientId;
                if (this.#clientSecret) {
                    params.body.client_secret = this.#clientSecret;
    
                }
            }

            if (typeof params.body != "string") params.body = JSON.stringify(params.body);
            return await fetch(url, params);
        }

    /**
     * Does nothing as CSRF tokens are not needed for this class
     * @returns `undefined`
     */
    async getCsrfToken() : Promise<undefined> {return undefined;}

    async receiveTokens(tokens : {
        access_token? : string|null,
        id_token? : string|null,
        refresh_token? : string|null
    }) : Promise<void> {

        if (tokens.access_token) {
            const payload = this.getTokenPayload(tokens.access_token);
            if (payload) {
                this.#accessToken = tokens.access_token;
                this.#accessTokenPayload = payload;
            }
            if (this.accessTokenResponseType == "localStorage") {
                localStorage.setItem(this.accessTokenName, tokens.access_token);
            } else if (this.accessTokenResponseType == "sessionStorage") {
                sessionStorage.setItem(this.accessTokenName, tokens.access_token);
            }
        }
        if (tokens.refresh_token) {
            const payload = this.getTokenPayload(tokens.refresh_token);
            if (payload) {
                this.#refreshToken = tokens.refresh_token;
                this.#refreshTokenPayload = payload;
            }
            if (this.refreshTokenResponseType == "localStorage") {
                localStorage.setItem(this.refreshTokenName, tokens.refresh_token);
            } else if (this.accessTokenResponseType == "sessionStorage") {
                sessionStorage.setItem(this.refreshTokenName, tokens.refresh_token);
            }
        }
        if (tokens.id_token) {
            const payload = await this.validateIdToken(tokens.id_token);
            this.#idTokenPayload = payload;
            if (this.idTokenResponseType == "localStorage") {
                localStorage.setItem(this.idTokenName, tokens.id_token);
            } else if (this.idTokenResponseType == "sessionStorage") {
                sessionStorage.setItem(this.idTokenName, tokens.id_token);
            }
        } 

    }

    /////////
    // Wrap flow functions

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */
    async clientCredentialsFlow(scope? : string) : 
    Promise<OAuthTokenResponse> {
        const resp = await super.clientCredentialsFlow(scope);
        await this.receiveTokens(resp);
        return resp;
    }

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */
    async passwordFlow(username: string,
        password: string,
        scope?: string) : 
        Promise<OAuthTokenResponse> {
            const resp = await super.passwordFlow(username, password, scope);
            await this.receiveTokens(resp);
            return resp;
        }

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */
    async deviceCodeFlow(scope?: string) : 
        Promise<OAuthDeviceAuthorizationResponse> {
            let url = this.authServerBaseUrl;
            if (!url.endsWith("/")) url += "/";
            url += this.deviceAuthorizationUrl;
            const resp = await super.startDeviceCodeFlow(url, scope);
            return resp;
        }

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */
    async mfaOtpComplete(
        mfaToken: string,
        otp: string) : 
        Promise<{
        access_token? : string, 
        refresh_token? : string, 
        id_token?: string, 
        expires_in? : number, 
        scope? : string, 
        token_type?: string, 
        error? : string, 
        error_description? : string}> {
            const resp = await super.mfaOtpComplete(mfaToken, otp);
            await this.receiveTokens(resp);
            return resp;
        }

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */

    async mfaOobComplete(mfaToken: string,
        oobCode: string,
        bindingCode: string) : Promise<OAuthTokenResponse> {
        const resp = await super.mfaOobComplete(mfaToken, oobCode, bindingCode);
        await this.receiveTokens(resp);
        return resp;
    }

    /**
     * See {@link @crossuath/common!OAuthClientBase}.  Calls the base function
     * then saves the tokens, as per the requested method
     * @param scope 
     */
    async refreshTokenFlow(refreshToken? : string) : 
        Promise<OAuthTokenResponse> {
        if (!refreshToken) {
            if (this.#refreshToken) {
                refreshToken = this.#refreshToken;
            } else {
                throw new CrossauthError(ErrorCode.InvalidToken, "Cannot refresh tokens: no refresh token present");
            }
        }
        const resp = await super.refreshTokenFlow(refreshToken);
        await this.receiveTokens(resp);
        return resp;
    }

    /**
     * Executes the authorization code flow
     * @param scope the scope to request
     * @param pkce whether or not to use PKCE.
     */
    async authorizationCodeFlow(scope?: string,
        pkce: boolean = false) : 
        Promise<void> {
        const resp  = await super.startAuthorizationCodeFlow(scope, pkce);
        //await this.receiveTokens(resp);
        if (resp.error || !resp.url) {
            const cerr = CrossauthError.fromOAuthError(
                resp.error??"Couldn't create URL for authorization code flow", 
                resp.error_description);
            CrossauthLogger.logger.debug(j({err: cerr}));
            throw cerr;
        }
        location.href = resp.url;
    }
}

