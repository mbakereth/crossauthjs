import { CrossauthError, CrossauthLogger, ErrorCode, j } from "@crossauth/common";

const TOLERANCE_SECONDS = 30;

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
    private autoRefreshActive = false;
    private mode :  "no-cors" | "cors" | "same-origin" = "cors";
    private credentials : "include" | "omit" | "same-origin" = "same-origin";

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
    constructor({ 
            sessionBaseUrl,
            oauthBaseUrl,
            bffPrefix,
            csrfHeader,
            credentials,
            mode,
            headers,
        }  : {
            sessionBaseUrl? : string,
            oauthBaseUrl? : string,
            bffPrefix? : string,
            csrfHeader? : string,
            credentials? : "include" | "omit" | "same-origin",
            mode? : "no-cors" | "cors" | "same-origin",
            headers? : {[key:string]:any},

        } = {}) {
        if (sessionBaseUrl) this.sessionBaseUrl = sessionBaseUrl;
        if (oauthBaseUrl) this.oauthBaseUrl = oauthBaseUrl;
        if (bffPrefix) this.bffPrefix = bffPrefix;
        if (csrfHeader) this.csrfHeader = csrfHeader;
        if (!(this.sessionBaseUrl.endsWith("/"))) this.sessionBaseUrl += "/";
        if (this.bffPrefix.startsWith("/") && this.bffPrefix.length > 1) {
            this.bffPrefix = this.bffPrefix.substring(1);
        }
        if (!(this.bffPrefix.endsWith("/"))) this.bffPrefix += "/";
        if (headers) this.headers = headers;
        if (mode) this.mode = mode;
        if (credentials) this.credentials = credentials;
    }

    /**
     * Any headers added here will be applied to all requests
     * @param header the header name eg `Access-Control-Allow-Origin`
     * @param value the header value
     */
    addHeader(header : string, value : string) {
        this.headers[header] = value;
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
     * @param tokenName 
     * @param csrfToken 
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
        const resp = await fetch(this.sessionBaseUrl + this.bffPrefix + endpoint, 
            {
                headers: this.headers,
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
            const resp = await fetch(this.sessionBaseUrl + tokenName + "_token", {
                method: "POST",
                headers: headers,
                mode: this.mode,
                credentials: this.credentials,
            })
            if (resp.status == 204) {
                return null;
            }
            const body = await resp.json();
            console.log(tokenName, body);
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
        const resp = await fetch(this.sessionBaseUrl + "have_" + tokenName + "_token", {
            method: "POST",
            headers: this.headers,
            mode: this.mode,
            credentials: this.credentials,
        })
        const json = await resp.json();
        if (!json.ok) throw new CrossauthError(ErrorCode.UnknownError, "Couldn't check token")
        return json.ok;
    }

    async startAutoRefresh(tokensToFetch : ("access"|"id")[] = ["access", "id"], 
        errorFn? : (msg : string, e? : CrossauthError) => void) {
    
        if (!this.autoRefreshActive) {
            this.autoRefreshActive = true;
            await this.scheduleAutoRefresh(tokensToFetch, errorFn);
        }
    }


    stopAutoRefresh() {
        this.autoRefreshActive = false;
    }

    private async scheduleAutoRefresh(tokensToFetch : ("access"|"id")[], 
        errorFn? : (msg : string, e? : CrossauthError) => void) {
            // Get CSRF token
            const csrfToken = await this.getCsrfToken();
            console.log("Csrf token", csrfToken)

            // Get tokens
            const idTask = tokensToFetch.includes("id") ? this.getIdToken(csrfToken) : undefined;
            const accessTask = tokensToFetch.includes("access") ? this.getAccessToken(csrfToken) : undefined;
            const refreshTask = this.getRefreshToken(csrfToken);
            const tokens = await Promise.all([idTask, accessTask, refreshTask]);
            const idToken = tokens[0];
            const accessToken = tokens[1];
            const refreshToken = tokens[2];
            if (!refreshToken) return;

            // get expiries
            let tokenExpiry : number | undefined = undefined;
            let refreshExpiry : number | undefined = undefined;
            if (idToken?.exp && 
                (tokenExpiry == undefined || idToken?.exp > tokenExpiry)) {
                    tokenExpiry = idToken.exp;
            }
            if (accessToken?.exp && 
                (tokenExpiry == undefined || accessToken?.exp > tokenExpiry)) {
                    tokenExpiry = accessToken.exp;
            }
            if (refreshToken?.exp && 
                (refreshExpiry == undefined || refreshToken?.exp > refreshExpiry)) {
                    refreshExpiry = refreshToken.exp;
            }
            const now = Date.now();
            console.log("now", now, "token expiry", tokenExpiry, "refresh expiry", refreshExpiry);

            // if neither access nor ID token expires, we have nothing to do
            if (!tokenExpiry) return;

            // renew token TOLERANCE_SECONDS before expiry
            const renewTime = tokenExpiry*1000 - now - TOLERANCE_SECONDS;
            if (renewTime < 0) return;

            // if refresh token is about to expire, don't try to use it
            if (refreshExpiry && refreshExpiry - TOLERANCE_SECONDS < renewTime) {
                return;
            }

            // schedule auto refresh task
            let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
            console.log("Refresh tokens: waiting", renewTime);
            await wait(renewTime);
            await this.autoRefresh(tokensToFetch, csrfToken, errorFn);

    }

    private async autoRefresh(tokensToFetch : ("access"|"id")[], csrfToken : string, errorFn? : (msg : string, e? : CrossauthError) => void,
        ) {
        if (this.autoRefreshActive) {
            try {
                let headers = {...this.headers};
                headers[this.csrfHeader] = csrfToken;
                        console.log("Requesting", this.oauthBaseUrl + "api/refreshtokens", csrfToken);
                const resp = await fetch(this.oauthBaseUrl + "api/refreshtokens", {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        ...headers,
                    },
                    mode: this.mode,
                    credentials: this.credentials,
                    body: JSON.stringify({
                        csrfToken
                    })
                });
                if (!resp.ok) {
                    CrossauthLogger.logger.error(j({msg: "Failed auto refreshing tokens", status: resp.status}));
    
                }
                console.log("Got resp", resp);
                const reply = await resp.json();
                console.log("Response", reply);

                if (reply.ok) {
                    await this.scheduleAutoRefresh(tokensToFetch, errorFn);
                }

                }
            catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({cerr: ce, msg: "Failed auto refreshing tokens"}));
                if (errorFn) {
                    errorFn(ce.message, ce);
                } else {
                    console.log(String(ce.message));
                }
            }
        }
    }
}