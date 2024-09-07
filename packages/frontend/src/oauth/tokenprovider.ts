// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
/**
 * USed by {@link OAuthAutoRefresher} to get tokens from the client
 */
export abstract class OAuthTokenProvider {

    /**
     * Gets a CSRF token from the server
     * @returns the CSRF token that can be included in
     *          the `X-CROSSAUTH-CSRF` header
     */
    getCsrfToken() : Promise<string|undefined> {return new Promise(_resolve => undefined);}

    /**
     * Fetches the expiry times for each token.
     * @param crfToken the CSRF token.  If emtpy
     * , one will be fetched before
     *        making the request
     * @returns for each token, either the expiry, `null` if it does not
     *          expire, or `undefined` if the token does not exist
     */
    abstract getTokenExpiries(tokensToFetch : ("access"|"id"|"refresh")[], 
        csrfToken? : string) : 
        Promise<{
            id: number | null | undefined,
            access: number | null | undefined,
            refresh: number | null | undefined
        }>;

    /**
     * Makes a fetch, adding in the requested token
     * @param url the URL to fetch
     * @param params parameters to add to the fetch
     * @param token which token to add.  Ignored as this client doesn't add tokens
     * @returns parsed JSON response
     */
    abstract jsonFetchWithToken(url: string,
        params: {[key:string]:any},
        token: "access" | "refresh") :
        Promise<Response>;

    abstract receiveTokens(tokens : {
        access_token? : string|null,
        id_token? : string|null,
        refresh_token? : string|null
    }) : Promise<void>;
}
