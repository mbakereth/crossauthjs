import { CrossauthError, ErrorCode} from "@crossauth/common";
import { URLSearchParams } from "url";

export type RedirectUriErrorFn = (client : OAuthBffClient,
    error : string,
    errorDescription? : string) => Promise<any>;

export type RedirectUriFn = (client : OAuthBffClient,
    code : string,
    state? : string) => Promise<any>;
    
export class OAuthBffClient {
    private baseUrl : string;
    private redirectUri : string;
    private headers : {[key:string]:string} = {};

    /**
     * Constructor
     * 
     * @param options
     *   - `baseUrl` the base url for BFF calls to the OAuth client
     *        (eg `https://myclient.com`).  Required: no default
     *   - `redirectUri` a URL on the site serving this app which the
     *      authorization server will redirect to with an authorization
     *      code.  See description in class documentation.
     */
    constructor({ 
            baseUrl,
            redirectUri,
        }  : {
            baseUrl : string,
            redirectUri : string,

        }) {
        this.baseUrl = baseUrl;
        if (!(this.baseUrl.endsWith("/"))) this.baseUrl += "/";
        this.redirectUri = redirectUri;
        if (!(this.redirectUri.endsWith("/"))) this.redirectUri += "/";
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
        errorFn : RedirectUriErrorFn) : Promise<any|undefined> {
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
}

