import { CrossauthError, ErrorCode} from "@crossauth/common";

export class OAuthBffClient {
    private baseUrl : string = "/";
    private bffPrefix : string = "bff";
    private csrfHeader : string = "X-CROSSAUTH-CSRF";
    private headers : {[key:string]:string} = {};

    /**
     * Constructor
     * 
     * @param param0
     *   - `baseUrl` the base url for BFF calls to the OAuth client
     *        (eg `https://myclient.com`).  Default is `/`
     *   - `bffPrefix` the base url for BFF calls to the OAuth client
     *        (eg `bff`, which is the default)
     *   - `csrfHeader` the header to put CSRF tokens into 
     *        (default `X-CROSSAUTH-CSRF`))
     */
    constructor({ 
            baseUrl,
            bffPrefix,
            csrfHeader,
        }  : {
            baseUrl? : string,
            bffPrefix? : string,
            csrfHeader? : string,

        } = {}) {
        if (baseUrl) this.baseUrl = baseUrl;
        if (bffPrefix) this.bffPrefix = bffPrefix;
        if (csrfHeader) this.csrfHeader = csrfHeader;
        if (!(this.baseUrl.endsWith("/"))) this.baseUrl += "/";
        if (this.bffPrefix.startsWith("/") && this.bffPrefix.length > 1) {
            this.bffPrefix = this.bffPrefix.substring(1);
        }
        if (!(this.bffPrefix.endsWith("/"))) this.bffPrefix += "/";
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
     * @returns 
     */
    async getCsrfToken(headers? : {[key:string]:string}) : Promise<string> {
        try {
            const params = {headers: this.headers};
            if (headers) params.headers = {...params.headers, ...headers}
            const resp = await fetch(this.baseUrl+"api/getcsrftoken", {});
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
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns the ID token payload or an empty object if there isn't one
     */
    async getIdToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<{[key:string]:any}|null>{
        return this.getToken("id", csrfToken, headers);
    }

    /**
     * Returns whether or not there is an ID token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns true or false
     */
    async haveIdToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<boolean>{
        return this.haveToken("id", csrfToken, headers);
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
    async getAccessToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<{[key:string]:any}|null>{
        return this.getToken("access", csrfToken, headers);
    }

    /**
     * Returns whether or not there is an access token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns true or false
     */
    async haveAccessToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<boolean>{
        return this.haveToken("access", csrfToken, headers);
    }

    /**
     * Fetches the refresh token from the client.
     * 
     * This only returns something if the refresh token was returned to the BFF
     * client in a previous OAuth call.  Otherwise it returns an empty JSON.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns the refresh token payload or an empty object if there isn't one
     */
    async getRefreshToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<{[key:string]:any}|null>{
        return this.getToken("refresh", csrfToken, headers);
    }

    /**
     * Returns whether or not there is a refresh token stored in the BFF server
     * for this client.
     * 
     * @param crfToken the CSRF token.  If emtpy, one will be fetched before
     *        making the request
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns true or false
     */
    async haveRefreshToken(csrfToken? : string, headers? : {[key:string]:any}) : Promise<boolean>{
        return this.haveToken("refresh", csrfToken, headers);
    }

    /**
     * Calls an API endpoint via the BFF server
     * @param tokenName 
     * @param csrfToken 
     * @param headers any additional headers to add (will be added to
     *         the ones given with {@link OAuthBffClient.addHeader} )
     * @returns the HTTP status code and the body or null
     */
    async api(method : "GET"|"POST"|"PUT"|"PATCH"|"OPTIONS"|"HEAD"|"DELETE",
        endpoint : string,
        body? : {[key:string]:any}, 
        csrfToken? : string,
        headers? : {[key:string]:any}) : 
        Promise<{status : number, body : {[key:string]:any}|null}> {
        if (!csrfToken && !(["GET", "HEAD", "OPTIONS"].includes(method))) {
            csrfToken = await this.getCsrfToken();
        }
        if (headers) { headers = {...this.headers, ...headers}; }
        else { headers = {...this.headers}; }
        if (csrfToken) headers[this.csrfHeader] = csrfToken;
        if (endpoint.startsWith("/")) endpoint = endpoint.substring(1);
        let params : {[key:string]:any} = {method, headers};
        if (body) params.body = body;
        const resp = await fetch(this.baseUrl + this.bffPrefix + endpoint, 
            params);
        let responseBody : {[key:string]:any} | null = null;
        if (resp.body) responseBody = await resp.json();
        return {status: resp.status, body: responseBody};
    }

    private async getToken(tokenName : string, 
        csrfToken? : string,
        headers? : {[key:string]:any}) : Promise<{[key:string]:any}|null>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        try {
            if (headers) { headers = {...this.headers, ...headers}; }
            else { headers = {...this.headers}; }                
            const resp = await fetch(this.baseUrl + tokenName + "_token", {
                method: "POST",
                headers: {
                    [this.csrfHeader]: csrfToken,
                    ...headers,
                }
            })
            if (resp.status == 204) {
                return null;
            }
            return await resp.json();
        } catch (e) {
            throw CrossauthError.asCrossauthError(e);
        }
    }

    private async haveToken(tokenName : string, 
        csrfToken? : string,
        headers? : {[key:string]:any}) : Promise<boolean>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        if (headers) { headers = {...this.headers, ...headers}; }
        else { headers = {...this.headers}; }                
        const resp = await fetch(this.baseUrl + "have_" + tokenName + "_token", {
            method: "POST",
            headers: {
                [this.csrfHeader]: csrfToken,
                ...headers,
            }
        })
        const json = await resp.json();
        if (!json.ok) throw new CrossauthError(ErrorCode.UnknownError, "Couldn't check token")
        return json.ok;
    }

}