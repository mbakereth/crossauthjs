import { URLSearchParams } from "url";
import { OAuthClientBase, OAuthTokenConsumerBase  } from '@crossauth/common'
import type { OAuthTokenResponse } from '@crossauth/common'
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
    "return" |
    "localStorage" |
    "sessionStorage" |
    "cookie";

export class OAuthClient extends OAuthClientBase {
    private resServerBaseUrl : string = "";
    private resServerHeaders : {[key:string]:string} = {};
    private accessTokenResponseType? : TokenResponseType = "return";
    private refreshTokenResponseType? : TokenResponseType = "return";
    private idTokenResponseType? : TokenResponseType = "return";
    private accessTokenName? : string = "CROSSAUTH_AT";
    private refreshTokenName? : string = "CROSSAUTH_RT";
    private idTokenName? : string = "CROSSAUTH_IT";

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
     *  For other options see {@link @crossauth/common/OAuthClientBase}.
     */
    constructor(options  : {
            authServerBaseUrl : string,
            stateLength? : number,
            verifierLength? : number,
            clientId? : string,
            clientSecret? : string,
            redirectUri? : string,
            codeChallengeMethod? : "plain" | "S256",
            tokenConsumer : OAuthTokenConsumerBase,
            fetchCredentials? : "same-origin"|"include",
            resServerBaseUrl? : string,
            accessTokenResponseType? : TokenResponseType,
            refreshTokenResponseType? : TokenResponseType,
            idTokenResponseType? : TokenResponseType,
            accessTokenName? : string,
            refreshTokenName? : string,
            idTokenName? : string,

        }) {
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
    }

    /**
     * Any headers added here will be applied to all requests
     * @param header the header name eg `Access-Control-Allow-Origin`
     * @param value the header value
     */
    addResServerHeader(header : string, value : string) {
        this.resServerHeaders[header] = value;
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
    async handleRedirectUri(receiveTokenFn? : ReceiveTokenFn, 
        errorFn? : ErrorFn) : Promise<any|undefined> {
        const url = new URL(window.location.href);
        if (url.origin + url.pathname != this.redirectUri) return undefined;
        const params = new URLSearchParams();
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

        if (error) return errorFn ? await errorFn(this, error, error_description) : {error, error_description};
        const resp = await this.redirectEndpoint(code, state, error, error_description);
        if (resp.error) return errorFn ? await errorFn(this, resp.error, resp.error_description) : resp;
        return receiveTokenFn ? await receiveTokenFn(this, resp) : resp;
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
    
}

