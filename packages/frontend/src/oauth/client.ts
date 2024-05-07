import { CrossauthError, ErrorCode} from "@crossauth/common";
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
 * This is the type for the function that is called when on a successful
 * response to the redirect Uri
 */
export type RedirectUriFn = (client : OAuthClient,
    code : string,
    state? : string) => Promise<any>;
    
export class OAuthClient extends OAuthClientBase {
    private resServerBaseUrl : string = "";
    private headers : {[key:string]:string} = {};

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

        }) {
        super(options);
        if (this.resServerBaseUrl != undefined) {
            this.resServerBaseUrl = options.resServerBaseUrl ?? "";
            if (this.resServerBaseUrl.length > 0 && 
                !(this.resServerBaseUrl.endsWith("/"))) {
                    this.resServerBaseUrl += "/";
                }
        }
    }

    /**
     * Processes the query parameters for a Redirect URI request.
     * 
     * Call this on page load to see if it was called as redirect URI.
     * 
     * To match, the URL must be the redirectUri value.
     * 
     * @param redirectUriFn this is called if `code` is in the query
     *        parameters
     * @param errorFn this is called if `error` is in the query
     *        parameters
     * @returns the returned value for `redirectUriFn` if it was called,
     *          the returned value of  `errorFn` if it was called,
     *          `undefined` if neither was called.
     */
    async handleRedirectUri(redirectUriFn : RedirectUriFn, 
        errorFn : ErrorFn) : Promise<any|undefined> {
        const url = new URL(window.location.href);
        if (url.origin + url.pathname != this.redirectUri) return undefined;
        const params = new URLSearchParams();
        let code : string|undefined = undefined;
        let state : string|undefined = undefined;
        let error : string|undefined = undefined;
        let errorDescription : string|undefined = undefined;
        for (const [key, value] of params) {
            if (key == "code") code = value;
            if (key == "state") state = value;
            if (key == "error") error = value;
            if (key == "error_description") errorDescription = value;
        }
        if (code) return await redirectUriFn(this, code, state);
        else if (error) return await errorFn(this, error, errorDescription);
        return undefined;
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
        return "";
    }

    /**
     * SHA256 and Base64-url-encodes the given test
     * @param plaintext the text to encode
     * @returns the SHA256 hash, Base64-url-encode
     */
    protected sha256(plaintext :string) : string {
        return "";
    }
    
}

