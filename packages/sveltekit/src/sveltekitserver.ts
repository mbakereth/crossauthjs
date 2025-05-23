// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { SvelteKitApiKeyServer, type SvelteKitApiKeyServerOptions } from './sveltekitapikey';
import { SvelteKitAuthorizationServer, type SvelteKitAuthorizationServerOptions } from './sveltekitoauthserver';
import {
    UserStorage,
    KeyStorage,
    Authenticator,
    setParameter,
    ParamType,
    OAuthClientStorage
 } from '@crossauth/backend';
import { CrossauthError, CrossauthLogger, ErrorCode, j, type User } from '@crossauth/common';
import { type Handle, type RequestEvent, type ResolveOptions, type MaybePromise } from '@sveltejs/kit';
import { SvelteKitOAuthClient } from './sveltekitoauthclient';
import type { SvelteKitOAuthClientOptions } from './sveltekitoauthclient';
import {
    SvelteKitOAuthResourceServer,
    type SvelteKitOAuthResourceServerOptions } from './sveltekitresserver';
import { OAuthTokenConsumer } from '@crossauth/backend';
import { SvelteKitSessionAdapter } from './sveltekitsessionadapter';


export interface SvelteKitServerOptions 
    extends SvelteKitSessionServerOptions, 
        SvelteKitApiKeyServerOptions,
        SvelteKitAuthorizationServerOptions,
        SvelteKitOAuthClientOptions,
        SvelteKitOAuthResourceServerOptions 
{
    /** User can set this to check if the user is an administrator.
     * By default, the admin booloean field in the user object is checked
     */
    isAdminFn?: (user : User) => boolean;
}

/**
 * This is the type for endpoint objects that provide `load` and `action`
 * exports for your pages.  See the {@link SvelteKitAdminEndpoints}
 * and {@link SvelteKitAdminEndpoints} for more details.
 */
export type SveltekitEndpoint = {
    load?: (event : RequestEvent) => Promise<{[key:string]:any}>,
    actions?: {[key:string]: (event : RequestEvent) => Promise<{[key:string]:any}>},
    get?: (event: RequestEvent) => Promise<Response>,
    post?: (event: RequestEvent) => Promise<Response>,
};

export type Resolver = (event: RequestEvent, opts?: ResolveOptions) => MaybePromise<Response>;

/**
 * The function to determine if a user has admin rights can be set
 * externally.  This is the default function if none other is set.
 * It returns true iff the `admin` field in the passed user is set to true.
 * 
 * @param user the user to test
 * @returns true or false
 */
function defaultIsAdminFn(user : User) : boolean {
    return user.admin == true;
}

/**
 * This is the main class for adding Crossauth to Svelekit applications.
 * 
 * To use it, create a file in your `src/lib` directory, eg
 * `src/lib/crossauthsessiion.ts`, something like this:
 * 
 * ```
 * export const prisma = new PrismaClient();
 * const userStorage = new PrismaUserStorage({prismaClient : prisma, userEditableFields: ["email"]});
 * const keyStorage = new PrismaKeyStorage({prismaClient : prisma});
 * const passwordAuthenticator = new LocalPasswordAuthenticator(userStorage);
 * export const crossauth = new SvelteKitServer({
 *     session: {
 *         keyStorage: keyStorage,
 *     }}, {
 *         userStorage: userStorage,
 *         authenticators: {
 *            localpassword: passwordAuthenticator,
 *         },
 *         loginProtectedPageEndpoints: ["/account"],
 *         redirect,
 *         error
 *     }); 
 * ```
 *
 * Note that we pass Sveltekit's `action` and `error` methods because, as
 * a module compiled without your Sveltekit application, this class has
 * no access to them otherwise, and they are use internally for things like
 * redirecting to your login page.
 * 
 * **Component Servers**
 * 
 * The above example creates a ccookie-based session server.  This class
 * has several optional component servers which can be instantiated 
 * individually or together.  They are:
 * 
 * - `sessionServer`   Session cookie management server.  Uses sesion ID
 *                     and CSRF cookies.  See {@link SvelteKitSessionServer}.
 * - `sessionAdapter`  If you are using only the oAuthClient and don't want
 *                     to use Crossauth's session server, you can implement
 *                     a minimal {@link SvelteKitSessionAdapter} instead.
 * - `oAuthAuthServer` OAuth authorization server.  See 
 *                     {@link SvelteKitAuthorizationServer}
 * - `oAuthClient`     OAuth client.  See {@link SvelteKitOAuthClient}.
 * - `oAuthClients`    Array of OAuth clients if you want more than one.  See {@link SvelteKitOAuthClient}.
 * - `oAuthResServer`  OAuth resource server.  See 
 *                     {@link SvelteKitOAuthResourceServer}.
 * 
 * Use either `oAuthClient` or `oAuthClients` but not both.
 * 
 * There is also an API key server which is not available as a variable as
 * it has no functions other than the hook it registers.
 * See {@link SvelteKitApiKeyServer}.
 * 
 * **Hooks**
 * 
 * This class provides hooks which you can add to by putting the following
 * in your `hooks.server.ts`:
 * 
 * ```
 * import { type Handle } from '@sveltejs/kit';
 * import { crossauth } from '$lib/server/crossauthsession';
 * import { CrossauthLogger } from '@crossauth/common';
 * export const handle: Handle = crossauth.hooks; 
 * ```
 * 
 * **Locals**
 * 
 * This will set the following in `event.locals`:
 * 
 *  - `user`: the logged in {@link @crossauth/common!User} or undefined,
 *  - `csrfToken` a CSRF token if the request is a `GET`, `HEAD` or `OPTIONS`,
 *  - `authType` authentication type, currently only `cookie`,
 *  - `apiKey` the valid API key if one was used,
 * - `oAuthAuthServer` OAuth authorization server.  See 
 *    {@link SvelteKitAuthorizationServer}
 *  - `accessTokenPayload` payload for the OAuth access token (not currently supported),
 *  - `authError` string error during authentication process (not currently used)
 *  - `authErrorDescription` error during authentication (not currently used),
 *  - `sessionId` session ID of logged in user, session ID for anonymous user, or undefined,
 *  - `scope` oAuth scope, not currently used,
 *   
 * **Authenticators**
 * 
 * One and two factor authentication is supported.  Authentication is provided
 * by classes implementing {@link Authenticator}.  They are passed as an 
 * object to this class, keyed on the name that appears in the user record
 * as `factor1` or `factor2`.  
 * 
 * For example, if you have passwords in your user database, you can use
 * {@link @crossauth/backend!LocalPasswordAuthenticator}.  If this method of authentication
 * is called `password` in the `factor1` field of the user record,
 * pass it in the `authenticators` parameter in the constructor with a key
 * of `password`.
 * 
 * **Use in Pages**
 *
 * For instructions about how to use this class in your endpoints, see
 * {@link SvelteKitUserEndpoints} and {@link SvelteKitAdminEndpoints}
 * for cookie-based session management.
 */
export class SvelteKitServer {

    /** The User storage that was passed during construction */
    readonly userStorage? : UserStorage;

    /** The session server if one was requested during construction */
    readonly sessionServer? : SvelteKitSessionServer;

    /** See class documentation.  If you pass `sessionServer` here instead,
     * `sessionAdapter` will also be set to it
     */
    readonly sessionAdapter? : SvelteKitSessionAdapter;

    /** The api key server if one was requested during construction */
    readonly apiKeyServer? : SvelteKitApiKeyServer;

    /** The OAuth authorization server if one was requested */
    readonly oAuthAuthServer? : SvelteKitAuthorizationServer;

    /** For adding in your `hooks.server.ts.  See class documentation
     * for details
     */
    readonly hooks : (Handle);
    private loginUrl = "/login";

    /**
     * User-defined function for determining whether a user is an admin.
     * 
     * The default is to look at the `admin` member of the
     * {@link @crossauth/common!User} object.
     */
    static isAdminFn: (user : User) => boolean = defaultIsAdminFn;

    /**
     * OAuth client instance
     */
    readonly oAuthClient? : SvelteKitOAuthClient;

    /**
     * Array of OAuth client instances as an alternative to `oAuthClient`
     */
    readonly oAuthClients? : SvelteKitOAuthClient[];

    /** OAuth resource server instance */
    readonly oAuthResServer? : SvelteKitOAuthResourceServer;

    private audience = "";

    /**
     * Constructor.
     * 
     * @param config an object with configuration:
     *   - `session` if you want a session (session cookie-based
     *     authentication), include this.  See the class documentation for
     *     details.  Note that the options in the third parameter of this
     *     constructor are concatinated with the options defined in
     *     `session.options`, so that you can have global as well as
     *     session server-specific configuration.
     *   - `apiKey` if passed, instantiate the session server (see class
     *     documentation).  The value is an object with a `keyStorage` field
     *     which must be present and should be the {@link KeyStorage} instance
     *     where API keys are stored.  A field called `options` whose
     *     value is an {@link SvelteKitApiKeyServerOptions} may also be
     *     provided.
     *   - `oAuthAuthServer` if passed, instantiate the session server (see class
     *      documentation).  The value is an object with a `keyStorage` field
     *      which must be present and should be the {@link KeyStorage} instance
     *      where authorization codes are stored.  This may be the same as
     *      the table storing session IDs or may be different.  A field
     *      called `clientStorage` with a value of type {@link OAuthClientStorage}
     *      must be provided and is where OAuth client details are stored.
     *      A field called `options` whose
     *      value is an {@link SvelteKitAuthorizationServerOptions} may also be
     *      provided.
     *    - `oAuthClient` if present, an OAuth client will be created.
     *      There must be a field called `authServerBaseUrl` and is the 
     *      base URL for the authorization server.  When validating access
     *      tokens, the `iss` claim must match this.
     *    - `oAuthClients` use this instead of `oAuthClient` if you want more
     *       than one OAuth client.
     *    - `oAuthResServer`  OAuth resource server.  See 
     *       {@link SvelteKitOAuthResourceServer}.
     *   - `options` Configuration that applies to the whole application,
     *     not just the session server.
     */
    constructor({
        session,
        sessionAdapter,
        apiKey,
        oAuthAuthServer,
        oAuthClient,
        oAuthClients,
        oAuthResServer,
        options,
    } : {
        session? : {
            keyStorage: KeyStorage, 
            options?: SvelteKitSessionServerOptions,
        },
        sessionAdapter? : SvelteKitSessionAdapter,
        apiKey? : {
            keyStorage: KeyStorage,
            options? : SvelteKitApiKeyServerOptions

        },
        oAuthAuthServer? : {
            clientStorage: OAuthClientStorage,
            keyStorage: KeyStorage,
            options? : SvelteKitAuthorizationServerOptions,
        },
        oAuthClient? : {
            authServerBaseUrl: string,
            options? : SvelteKitOAuthClientOptions,
        },
        oAuthClients? : {
            authServerBaseUrl: string,
            options? : SvelteKitOAuthClientOptions,
        }[],
        oAuthResServer? : {
            options? : SvelteKitOAuthResourceServerOptions,
        },
        options? : SvelteKitServerOptions}) {

        if (!options) options = {};
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL", false);
        if (options.isAdminFn) SvelteKitServer.isAdminFn = options.isAdminFn;

        let authenticators : {[key:string]: Authenticator} = {};
        if (options.authenticators) authenticators = options.authenticators;

        this.userStorage = options.userStorage;
        if (session) {
            if (!authenticators) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "If using session management, must supply authenticators")
            }
            this.sessionServer = new SvelteKitSessionServer(session.keyStorage, authenticators, {...session.options, ...options});
            this.sessionAdapter = this.sessionServer;
        } else if (sessionAdapter) {
            this.sessionAdapter = sessionAdapter;
        }

        if (apiKey) {
            if (!this.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Must define a user storage if using API keys");
            this.apiKeyServer = new SvelteKitApiKeyServer(this.userStorage,
                apiKey.keyStorage,
                { ...options, ...apiKey.options });
        }

        if (oAuthAuthServer) {
            let extraOptions : SvelteKitAuthorizationServerOptions = {};
            if (this.loginUrl) extraOptions.loginUrl = this.loginUrl;
            this.oAuthAuthServer = new SvelteKitAuthorizationServer(
                this,
                oAuthAuthServer.clientStorage,
                oAuthAuthServer.keyStorage,
                authenticators,
                { ...extraOptions, ...options, ...oAuthAuthServer.options });
        }
    
        if (oAuthClient && oAuthClients) {
            throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both oAuthClient and oAuthClients")
        }
        if (oAuthClient) {
            this.oAuthClient = new SvelteKitOAuthClient(this,
                oAuthClient.authServerBaseUrl,
                { ...options, ...oAuthClient.options });
        }

        if (oAuthClients) {
            this.oAuthClients = [];
            for (let client of oAuthClients) {
                this.oAuthClients.push(
                    new SvelteKitOAuthClient(this,
                    client.authServerBaseUrl,
                    { ...options, ...client.options })
                );
            }
        }
        

        if (oAuthResServer) {
            setParameter("audience", ParamType.String, this, options, "OAUTH_AUDIENCE", true);
            this.oAuthResServer = new SvelteKitOAuthResourceServer( 

                [new OAuthTokenConsumer(this.audience, options)],
                {sessionAdapter: this.sessionAdapter, ...oAuthResServer.options, ...options}
            )
        }

        this.hooks = async ({event, resolve}) => {

            const newEvent = await this.unresolvedHooks(event);            
            if (newEvent  instanceof Response) return newEvent;
            return await resolve(newEvent);

        }
    }

    async unresolvedHooks(event : RequestEvent) {

        // reset all locals
        event.locals.user = undefined;
        event.locals.sessionId = undefined;
        event.locals.csrfToken = undefined;
        event.locals.authType = undefined;
        event.locals.scope = undefined;

        let otherLoginsTried = false;
        if (this.sessionServer) {

            // session hook
            let resp = await this.sessionServer.sessionHook({event});
            if (resp.status == 302) {
                let loc : string|undefined = undefined;
                for (let h of resp.headers) {
                    if (h.name == "location") loc = h.value;
                }
                if (loc) await this.sessionServer.redirect(302, loc);
            }

            // two FA hook
            const ret = this.userStorage ?  await this.sessionServer.twoFAHook({event}) : undefined;
            if (!(ret && ret.twofa) && !event.locals.user) {

                // try other means of logging in before redirecting to login page
                // API server hook
                if (this.apiKeyServer) {
                    await this.apiKeyServer.hook({event});
                }

                // OAuth client hook
                if (this.oAuthClient) {
                    await this.oAuthClient.hook({event});
                }

                // OAuth res server hook
                if (this.oAuthResServer?.hook) {
                    const resp = await this.oAuthResServer.hook({event});
                    if (resp) return resp;
                }

                otherLoginsTried = true;

                if (!event.locals.user) {
                    if (this.sessionServer.isLoginPageProtected(event))  {
                        CrossauthLogger.logger.debug(j({msg: "Page is login protected and we don't have credentials"}))
                        if (this.loginUrl) {
                            /*let redirect_uri = event.url.pathname;
                            if (event.url.searchParams) {
                                redirect_uri += "%3F";
                                event.url.searchParams.forEach((value, key) => {
                                    redirect_uri += encodeURIComponent(key) + "%3D" + encodeURIComponent(value)
                                });
                            }*/
                            let redirect_uri =encodeURIComponent(event.request.url);
                            return new Response(null, {status: 302, headers: {location: this.loginUrl + "?next=" + redirect_uri}});
                        }
                        return this.sessionServer.error(401, "Unauthorized");
    
                    }
                    if (this.sessionServer.isLoginApiProtected(event)) 
                        return this.sessionServer.error(401, "Unauthorized");
    
                }
            }
            
            if (!(ret && ret.twofa) && this.sessionServer.isAdminPageEndpoint(event) &&
                (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))
            ) {
                    if (this.sessionServer.unauthorizedUrl) {
                        return new Response(null, {status: 302, headers: {location: this.sessionServer.unauthorizedUrl}});
                    }
                    return this.sessionServer.error(401, "Unauthorized");
            }
            if (!(ret && ret.twofa) && this.sessionServer.isAdminApiEndpoint(event) &&
                (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user))) {
                    return this.sessionServer.error(401, "Unauthorized");
            }
            if (ret?.response) return ret.response;    
        }

        if (!otherLoginsTried) {
            // API server hook
            if (this.apiKeyServer) {
                await this.apiKeyServer.hook({event});
            }

            // OAuth client hook
            if (this.oAuthClient) {
                await this.oAuthClient.hook({event});
            }

            // OAuth res server hook
            if (this.oAuthResServer?.hook) {
                const resp = await this.oAuthResServer.hook({event});
                if (resp) return resp;
            }
        }
        
        return event;

    }

    /**
     * See class documentation for {@link SvelteKitUserEndpoints}.
     * 
     * This is an empty `load` which serves no purpose other than to stop
     * Typescript complaining that `load` may be undefined.
     * @param _event Sveltekit event object
     * @returns an empty object
     */
    dummyLoad : (event : RequestEvent) => Promise<{[key:string]:any}> = async (_event) => {return {}};

    /**
     * See class documentation for {@link SvelteKitUserEndpoints}.
     * 
     * This is an empty `load` which serves no purpose other than to stop
     * Typescript complaining that `actions` may be undefined.
     * @returns an empty object
     */
    dummyActions : {[key:string]: (event : RequestEvent) => Promise<{[key:string]:any}>} = {};

    /**
     * See class documentation for {@link SvelteKitUserEndpoints}.
     * 
     * This is an empty `bff action` which serves no purpose other than to stop
     * Typescript complaining that the action may be undefined.
     * @param _event Sveltekit event object
     * @returns an empty object
     */
    dummyBff : (event : RequestEvent) => Promise<{[key:string]:any}> = async (_event) => {return {status: 500, body: {error: "Unimplemented"}}};

    /**
     * It is not possible to get any meaninfgul info about an exception class
     * with `typeof` or `instanceof`.  This method heuristically determines
     * if an exception is a Sveltekit redirect.  It is used internally
     * @param e an exception
     * @returns true or false
     */
    static isSvelteKitRedirect(e : any) {
        return (typeof e == "object" && e != null && "status" in e && "location" in e);
    }

    /**
     * It is not possible to get any meaninfgul info about an exception class
     * with `typeof` or `instanceof`.  This method heuristically determines
     * if an exception is a Sveltekit error.  It is used internally
     * @param e an exception
     * @returns true or false
     */
    static isSvelteKitError(e : any, status? : number) {
        if (status) {
            return (typeof e == "object" && e != null && "status" in e && "text" in e && "message" in e && e.status == status);
        } 
        return (typeof e == "object" && e != null && "status" in e && "text" in e && "message" in e);

    }
}
