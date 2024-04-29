import { CrossauthError } from "@crossauth/common";

export class OAuthBffClient {
    private baseUrl : string;
    private bffPrefix : string;

    /**
     * Constructor
     * 
     * @param baseUrl the base url for BFF calls to the OAuth client
     *        (eg `https://myclient.com`).  Default is `/`
     * @param bffBaseUrl the base url for BFF calls to the OAuth client
     *        (eg `bff`, which is the default)
     */
    constructor(baseUrl : string = "/", bffPrefix : string = "bff") {
        this.baseUrl = baseUrl;
        this.bffPrefix = bffPrefix;
        if (!(this.baseUrl.endsWith("/"))) this.baseUrl += "/";
        if (this.bffPrefix.startsWith("/") && this.bffPrefix.length > 1) {
            this.bffPrefix = this.bffPrefix.substring(1);
        }
        if (!(this.bffPrefix.endsWith("/"))) this.bffPrefix += "/";
    }

    /**
     * Gets a CSRF token from the server
     * @returns 
     */
    async getCsrfToken() : Promise<string> {
        try {
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
     * @returns the ID token payload or an empty object if there isn't one
     */
    async getIdToken(csrfToken? : string) : Promise<{[key:string]:any}>{
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
     * @returns the access token payload or an empty object if there isn't one
     */
    async getAccessToken(csrfToken? : string) : Promise<{[key:string]:any}>{
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
    async getRefreshToken(csrfToken? : string) : Promise<{[key:string]:any}>{
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

    private async getToken(tokenName : string, csrfToken? : string) : Promise<{[key:string]:any}>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        try {
            const resp = await fetch(this.baseUrl + this.bffPrefix + tokenName + "_token", {
                method: "POST",
                headers: {
                    "X-CROSSAUTH-CSRF": csrfToken,
                }
            })
            const json = await resp.json();
            if (!json.ok) throw CrossauthError.asCrossauthError(json);
            return json;
        } catch (e) {
            throw CrossauthError.asCrossauthError(e);
        }
    }

    private async haveToken(tokenName : string, csrfToken? : string) : Promise<boolean>{
        if (!csrfToken) csrfToken = await this.getCsrfToken();
        const resp = await fetch(this.baseUrl + this.bffPrefix + "have_" + tokenName + "_token", {
            method: "POST",
            headers: {
                "X-CROSSAUTH-CSRF": csrfToken,
            }
        })
        const json = await resp.json();
        if (!json.ok) throw CrossauthError.asCrossauthError(json);
        return json.ok;
    }

}