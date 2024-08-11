import type { RequestEvent, MaybePromise } from '@sveltejs/kit';
import {
    CrossauthError,
    CrossauthLogger,
    j,
    ErrorCode,
    type User } from '@crossauth/common';
import {
    setParameter,
    ParamType,
    OAuthResourceServer,
    UserStorage } from '@crossauth/backend';
import type { OAuthResourceServerOptions } from '@crossauth/backend';
import { OAuthTokenConsumer } from '@crossauth/backend';

/**
 * Options for {@link SvelteKitOAuthResourceServer}
 */
export interface SvelteKitOAuthResourceServerOptions extends OAuthResourceServerOptions {

    /** If you set this and your access tokens have a user (`sub` claim), 
     * the `user` field in the request will be populated with a valid
     * access token,
     */
    userStorage? : UserStorage;

    /**
     * If you enabled `protectedEndpoints` in 
     * {@link FastifyOAuthResourceServer.constructor}
     * and the access token is invalid, a 401 reply will be sent before
     * your endpoint is hit.  This will be the body,  Default {}.
     */
        errorBody? : {[key:string]:any};

    /**
     * If you define this, matching resource server endpoints will return
     * a status code of 401 Access Denied if the key is invalid or the 
     * given scopes are not present.
     */
    protectedEndpoints? : {[key:string]: {scope? : string[], acceptSessionAuthorization?: boolean}},
}

/**
 * OAuth resource server. 
 * 
 * You can subclass this, simply instantiate it, or create it through
 * {@link SvelteKitServer}.  
 * 
 * There are two way of using this class.  If you don't set
 * `protectedEndpoints` in 
 * {@link SvelteKitAuthResourceServer.constructor}, then in your
 * protected endpoints, call {@link SvelteKitOAuthResourceServer.authorized}
 * to check if the access token is valid and get any user credentials.
 * 
 * If you do set `protectedEndpoints` in 
 * {@link SvelteKitOAuthResourceServer.constructor}
 * then a hook is created.
 * The hook
 * hook will set the `accessTokenPayload`, `user` and `scope` fields 
 * on the event locals based on the content
 * of the access token in the `Authorization` header if it is valid.
 * If it is not valid it will set the `authError` and `authErrorDescription`.
 * If the access token is invalid, or there is an error, a 401 or 500
 * response is sent before executing your endpoint code.  As per
 * OAuth requirements, if the response is a 401, the WWW-Authenticate header
 * is set.  If a scope is required this is included in that header.
 */
export class SvelteKitOAuthResourceServer extends OAuthResourceServer {

    private userStorage? : UserStorage;
    private errorBody : {[key:string]:any} = {};
    private protectedEndpoints : {[key:string]: {scope? : string[], acceptSessionAuthorization?: boolean}} = {};
    /**
     * Hook to check if the user is logged in and set data in `locals`
     * accordingly.
     */
    readonly hook? : (input: {event: RequestEvent}) => MaybePromise<Response|undefined>;

    /**
     * Constructor
     * @param tokenConsumers the token consumers, one per issuer
     * @param options See {@link SvelteKitOAuthResourceServerOptions}
     */
    constructor(
        tokenConsumers: OAuthTokenConsumer[],
        options : SvelteKitOAuthResourceServerOptions = {}) {
        super(tokenConsumers, options);

        setParameter("errorBody", ParamType.Json, this, options, "OAUTH_RESSERVER_ACCESS_DENIED_BODY");
        this.userStorage = options.userStorage;

        if (options.protectedEndpoints) {
            const regex = /^[!#\$%&'\(\)\*\+,\\.\/a-zA-Z\[\]\^_`-]+/;
            for (const [key, value] of Object.entries(options.protectedEndpoints)) {
                if (!key.startsWith("/")) {
                    throw new CrossauthError(ErrorCode.Configuration, "protected endpoints must be absolute paths without the protocol and hostname");
                }
                if (value.scope) {
                    value.scope.forEach((s : string) => {
                        if (!(regex.test(s))) throw new CrossauthError(ErrorCode.Configuration, "Illegal characters in scope " + s);
                    });
                }
            }
            this.protectedEndpoints = options.protectedEndpoints;
        }
            
        if (options.protectedEndpoints) {
            // validate access token and put in request, along with any errors
            this.hook = async ({ event }) => {
                
                // don't authenticate if user already logged in with a session
                //if (request.user && request.authType == "cookie") return;

                const urlWithoutQuery = event.url.pathname;
                if (!(urlWithoutQuery in this.protectedEndpoints)) return;

                const authResponse = await this.authorized(event);

                // If we are also we are not allowing authentication by
                // and the user is valid, session cookie for this endpoint
                if (!(event.locals.user && event.locals.authType == "cookie" 
                    && this.protectedEndpoints[urlWithoutQuery].acceptSessionAuthorization!=true )) {
                    if (!authResponse) {
                        event.locals.authError = "access_denied"
                        event.locals.authErrorDescription = "No access token";
                        const authenticateHeader = this.authenticateHeader(event);
                        return new Response(JSON.stringify(this.errorBody), {headers: {
                            "content-type": "application/json", 
                            'WWW-Authenticate': authenticateHeader},
                            status: 401});
                    }
                    if (!authResponse.authorized) {
                        const authenticateHeader = this.authenticateHeader(event);
                        return new Response(JSON.stringify(this.errorBody), {headers: {
                            "content-type": "application/json", 
                            'WWW-Authenticate': authenticateHeader},
                            status: 401});
                    }
                }

                if (authResponse) {
                    // we have a valid token - set the user from it
                    event.locals.accessTokenPayload = authResponse.tokenPayload;
                    event.locals.user = authResponse.user;
                    if (authResponse.tokenPayload?.scope) {
                        if (Array.isArray(authResponse.tokenPayload.scope)) {
                            let scope : string[] = [];
                            for (let tokenScope of authResponse.tokenPayload.scope) {
                                if (typeof tokenScope == "string") {
                                    scope.push(tokenScope);
                                }
                            }
                            event.locals.scope = scope;
                        } else if (typeof authResponse.tokenPayload.scope == "string") {
                            event.locals.scope = authResponse.tokenPayload.scope.split(" ");
                        }
                    }
                    if (this.protectedEndpoints[urlWithoutQuery].scope) {
                        for (let scope of this.protectedEndpoints[urlWithoutQuery].scope??[]) {
                            if (!event.locals.scope || !(event.locals.scope.includes(scope))
                                && this.protectedEndpoints[urlWithoutQuery].acceptSessionAuthorization!=true) {
                                CrossauthLogger.logger.warn(j({msg: "Access token does not have sufficient scope",
                                    username: event.locals.user?.username, url: event.request.url}));
                                    event.locals.scope = undefined;
                                    event.locals.accessTokenPayload = undefined;
                                    event.locals.user = undefined;
                                    event.locals.authError = "access_denied";
                                    event.locals.authErrorDescription = "Access token does not have sufficient scope";
                                    const authenticateHeader = this.authenticateHeader(event);
                                    return new Response(JSON.stringify(this.errorBody), {headers: {
                                        "content-type": "application/json", 
                                        'WWW-Authenticate': authenticateHeader},
                                        status: 401});
                            }
                        }
                    }

                    event.locals.authType = "oauth";
                    event.locals.authError = authResponse?.error
                    if (authResponse?.error == "access_denied") {
                        const authenticateHeader = this.authenticateHeader(event);
                        return new Response(JSON.stringify(this.errorBody), {headers: {
                            "content-type": "application/json", 
                            'WWW-Authenticate': authenticateHeader},
                            status: 401});
                    } else if (authResponse?.error) {
                        return new Response(JSON.stringify(this.errorBody), {headers: {
                            "content-type": "application/json", },
                            status: 500});
                    } 
                    event.locals.authErrorDescription = authResponse?.error_description;
                    CrossauthLogger.logger.debug(j({msg: "Resource server url", url: event.request.url, authorized: event.locals.accessTokenPayload!= undefined}));
                }
            };
        }
        
    }

    private authenticateHeader(event : RequestEvent) : string {
        const urlWithoutQuery = event.url.pathname;
        if (urlWithoutQuery in this.protectedEndpoints) {
            let header = "Bearer";
            if (this.protectedEndpoints[urlWithoutQuery].scope) {
                header += ' scope="' + (this.protectedEndpoints[urlWithoutQuery].scope??[]).join(" ");
            }
            return header;
        }
        return "";
    }


    /**
     * If there is no bearer token, returns `undefinerd`.  If there is a
     * bearer token and it is a valid access token, returns the token
     * payload.  If there was an error, returns it in OAuth form.
     * 
     * @param event the SvelteKit request event
     * @returns an object with the following fiekds
     *   - `authorized` : `true` or `false`
     *   - `tokenPayload` : the token payload if the token is valid
     *   - `error` : if the token is not valid
     *   - `error_description` : if the token is not valid
     *   - `user` set if `sub` is defined in the token, a userStorage has
     *     been defined and it matches
     */
    async authorized(event : RequestEvent) : Promise<{
        authorized: boolean, 
        tokenPayload?: {[key:string]: any}, 
        user? : User,
        error? : string, 
        error_description?: string}|undefined> {

        try {
            const header = event.request.headers.get("authorization");
            if (header && header.startsWith("Bearer ")) {
                const parts = header.split(" ");
                if (parts.length == 2) {
                    let user : User|undefined = undefined;
                    const resp = await this.accessTokenAuthorized(parts[1]);
                    if (resp) {
                        if (resp.sub && this.userStorage) {
                            const userResp = 
                                await this.userStorage.getUserByUsername(resp.sub);
                            if (userResp) user = userResp.user;
                        }
                        return {authorized: true, tokenPayload: resp, user: user};
                    } else {
                        return {authorized: false};
                    }
                }
            }    
        } catch (e) {
            const ce = e as CrossauthError;
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({cerr: ce}));
            event.locals.authError = "server_error";
            event.locals.authErrorDescription = ce.message;
            return {authorized: false, error: "server_error", error_description: ce.message};
        }
        return undefined;
    }
}