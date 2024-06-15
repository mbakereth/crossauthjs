import { CrossauthError, ErrorCode } from "@crossauth/common";
import { OAuthAutoRefresher } from './autorefresher.ts';

/**
 * A browser-side OAuth client designed with work with the
 * backend-for-frontend (BFF) mode of the backend OAuth client.
 * 
 * See {@link @crossauth/fastify!FastifyOAuthClient}.
 */
export class OAuthBffClient {
    private sessionBaseUrl : string = "/";
    private oauthBaseUrl : string = "/";
    private bffPrefix : string = "bff";
    private csrfHeader : string = "X-CROSSAUTH-CSRF";
    private headers : {[key:string]:string} = {};
    private mode :  "no-cors" | "cors" | "same-origin" = "cors";
    private credentials : "include" | "omit" | "same-origin" = "same-origin";
    private autoRefresher : OAuthAutoRefresher;

    /**
     * Constructor
     * 
     * @param options
     *   - `sessionBaseUrl` the base url for calls to the client session manager
     *        (eg `https://myclient.com`).  Default is `/`
     *   - `oauthBaseUrl` the base url for calls to the oauth client backend
     *        (eg `https://myclient.com`).  Default is `/`
     *   - `bffPrefix` the base url for BFF calls to the OAuth client
     *        (eg `bff`, which is the default)
     *   - `csrfHeader` the header to put CSRF tokens into 
     *        (default `X-CROSSAUTH-CSRF`))
     *   - `mode` overrides the default `mode` in fetch calls
     *   - `credentials` - overrides the default `credentials` for fetch calls
     *   - `headers` - adds headers to fetfh calls
     */
    constructor(options : {
            sessionBaseUrl? : string,
            oauthBaseUrl? : string,
            bffPrefix? : string,
            csrfHeader? : string,
            credentials? : "include" | "omit" | "same-origin",
            mode? : "no-cors" | "cors" | "same-origin",
            headers? : {[key:string]:any},

        } = {}) {
        if (options.sessionBaseUrl) this.sessionBaseUrl = options.sessionBaseUrl;
        if (options.oauthBaseUrl) this.oauthBaseUrl = options.oauthBaseUrl;
        if (options.bffPrefix) this.bffPrefix = options.bffPrefix;
        if (options.csrfHeader) this.csrfHeader = options.csrfHeader;
        if (!(this.sessionBaseUrl.endsWith("/"))) this.sessionBaseUrl += "/";
        if (this.bffPrefix.startsWith("/") && this.bffPrefix.length > 1) {
            this.bffPrefix = this.bffPrefix.substring(1);
        }
        if (!(this.bffPrefix.endsWith("/"))) this.bffPrefix += "/";
        if (options.headers) this.headers = options.headers;
        if (options.mode) this.mode = options.mode;
        if (options.credentials) this.credentials = options.credentials;
        this.autoRefresher = new OAuthAutoRefresher({
            ...options,
            autoRefreshUrl: this.oauthBaseUrl + "api/refreshtokens",
            tokenProvider: this,
        });
    }

    /**
     * Gets a CSRF token from the server
     * @returns the CSRF token that can be included in
     *          the `X-CROSSAUTH-CSRF` header
     */
    async getCsrfToken() : Promise<string> {
        try {
            const resp = await fetch(this.sessionBaseUrl+"api/getcsrftoken", {
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
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns the ID token payload or an empty object if there isn't one
     */
    async getIdToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        return this.getToken("id", csrfToken);
    }

    /**
     * Returns whether or not there is an ID token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveIdToken(csrfToken? : string) : Promise<boolean>{
        return this.haveToken("id", csrfToken);
    }

    /**
     * Fetches the access token from the client.
     * 
     * This only returns something if the access token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns the access token payload or an empty object if there isn't one
     */
    async getAccessToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        return this.getToken("access", csrfToken);
    }

    /**
     * Returns whether or not there is an access token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveAccessToken(csrfToken? : string) : Promise<boolean>{
        return this.haveToken("access", csrfToken);
    }

    /**
     * Fetches the refresh token from the client.
     * 
     * This only returns something if the refresh token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns the refresh token payload or an empty object if there isn't one
     */
    async getRefreshToken(csrfToken? : string) : Promise<{[key:string]:any}|null>{
        return this.getToken("refresh", csrfToken);
    }

    /**
     * Returns whether or not there is a refresh token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @returns true or false
     */
    async haveRefreshToken(csrfToken? : string) : Promise<boolean>{
        return this.haveToken("refresh", csrfToken);
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
            headers[this.csrfHeader] = csrfToken;
        }
        if (endpoint.startsWith("/")) endpoint = endpoint.substring(1);
        let params : {body? : string}= {};
        if (body) params.body = JSON.stringify(body);
        const resp = await fetch(this.oauthBaseUrl + this.bffPrefix + endpoint, 
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

    private async getToken(tokenName : string, 
        csrfToken? : string,) : Promise<{[key:string]:any}|null>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        let headers = {...this.headers};
        headers[this.csrfHeader] = csrfToken;
        try {
            const resp = await fetch(this.oauthBaseUrl + tokenName + "_token", {
                method: "POST",
                headers: headers,
                mode: this.mode,
                credentials: this.credentials,
            })
            if (resp.status == 204) {
                return null;
            }
            const body = await resp.json();
            return body;
            //return await resp.json();
        } catch (e) {
            throw CrossauthError.asCrossauthError(e);
        }
    }

    private async haveToken(tokenName : string, 
        csrfToken? : string) : Promise<boolean>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        let headers = {...this.headers};
        headers[this.csrfHeader] = csrfToken;
        const resp = await fetch(this.oauthBaseUrl + "have_" + tokenName + "_token", {
            method: "POST",
            headers: this.headers,
            mode: this.mode,
            credentials: this.credentials,
        })
        const json = await resp.json();
        if (!json.ok) throw new CrossauthError(ErrorCode.UnknownError, "Couldn't check token")
        return json.ok;
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
    async getTokenExpiries(tokensToFetch : ("access"|"id"|"refresh")[], 
        csrfToken? : string) : 
        Promise<{
            id: number | null | undefined,
            access: number | null | undefined,
            refresh: number | null | undefined
        }> {

            // Get tokens
            const idTask = tokensToFetch.includes("id") ? this.getIdToken(csrfToken) : undefined;
            const accessTask = tokensToFetch.includes("access") ? this.getAccessToken(csrfToken) : undefined;
            const refreshTask = tokensToFetch.includes("refresh") ? this.getRefreshToken(csrfToken) : undefined;
            const tokens = await Promise.all([idTask, accessTask, refreshTask]);
            const idToken = tokens[0];
            const accessToken = tokens[1];
            const refreshToken = tokens[2];

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
        }

    /**
     * Makes a fetch, adding in the requested token
     * @param url the URL to fetch
     * @param params parameters to add to the fetch
     * @param token which token to add
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