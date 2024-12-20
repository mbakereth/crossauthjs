// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import fastify, {
    type FastifyInstance,
    type FastifyRequest,
    type FastifyReply } from 'fastify';
import { Server, IncomingMessage, ServerResponse } from 'http'
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import cors from '@fastify/cors'
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import nunjucks from "nunjucks";
import { OAuthTokenConsumer } from '@crossauth/backend';

import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    j } from '@crossauth/common';
import {
    KeyStorage,
    OAuthClientStorage,
    Authenticator,
    Crypto,
    setParameter,
    ParamType } from '@crossauth/backend';
import { FastifySessionServer } from './fastifysession';
import { FastifySessionAdapter } from './fastifysessionadapter';
import type {
    FastifySessionServerOptions,
    CsrfBodyType } from './fastifysession';
import {
    FastifyApiKeyServer,
    type FastifyApiKeyServerOptions } from './fastifyapikey';
import {
    FastifyAuthorizationServer,
    type FastifyAuthorizationServerOptions } from './fastifyoauthserver';
import {
    FastifyOAuthClient,
    type FastifyOAuthClientOptions } from './fastifyoauthclient';
import {
    FastifyOAuthResourceServer,
    type FastifyOAuthResourceServerOptions } from './fastifyresserver';
import { type User } from '@crossauth/common';

export const ERROR_400 = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>400 Bad Request</h1>
<p>The server was unable to handle your request.</p>
</body></html>
`

export const ERROR_401 = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>401 Unauthorized</h1>
<p>You are not authorized to access this URL.</p>
</body></html>
`
export const ERROR_403= `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>403 Forbidden</h1>
<p>You are not authorized to make this request.</p>
</body></html>
`

export const ERROR_500 = `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Server Error</title>
</head><body>
<h1>500 Error</h1>
<p>Sorry, an unknown error has occured</p>
</body></html>
`
export const DEFAULT_ERROR = {
    400: ERROR_400,
    401: ERROR_401,
    500: ERROR_500
}

/**
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifyServerOptions extends 
    FastifySessionServerOptions, 
    FastifyApiKeyServerOptions, 
    FastifyAuthorizationServerOptions, 
    FastifyOAuthClientOptions, 
    FastifyOAuthResourceServerOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** If this is passed, it is registered as a Nunjucks view folder with autoscape on */
    views? : string,

    isAdminFn?: (user : User) => boolean;

    /**
     * Config for `@fastify/cors`
     */
    cors? : {[key:string]:any}


};

/**
 * Type for the function that is called to pass an error back to the user
 * 
 * The function is passed this instance, the request that generated the
 * error, the response object for sending the respons to and the
 * exception that was raised.
 */
export type FastifyErrorFn = (server: FastifyServer,
    request: FastifyRequest,
    reply: FastifyReply,
    ce: CrossauthError) => Promise<FastifyReply>;

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
 * This class provides a complete (but without HTML files) auth backend server 
 * for Fastify applications
 * 
 * If you do not pass a Fastify app to this class, it will create one.  
 * By default, pages are rendered
 * with Nunjucks.  If you prefer another renderer that is compatible with 
 * Fastify, create your
 * own Fastify app and configure the renderer using @fastify/view.
 * 
 * By default, all views are expected to be in a directory called `views` 
 * relative to the directory the
 * server is started in.  This can be overwritten by setting the `views` option.
 * 
 * Note that `views`, and the Nunjucks pages are not used by the API 
 * endpoints (those starting in /api).  These just return JSON.
 * 
 * **Component Servers**
 * 
 * This class contains a number of servers which don't all have to be
 * created, depending on what authentication you want to support.  If
 * instantiated, they can work together.
 * 
 * - `sessionServer`   Session cookie management server.  Uses sesion ID
 *                     and CSRF cookies.  See {@link FastifySessionServer}.
 * - `sessionAdapter`  If you want an OAuth client but not want to use
 *                     Crossauth's session server, you can provide your own
 *                     with this.  Won't work with auth server.
 * - `oAuthAuthServer` OAuth authorization server.  See 
 *                     {@link FastifyAuthorizationServer}
 * - `oAuthClient`     OAuth client.  See {@link FastifyOAuthClient}.
 * - `oAuthClients`    An array of OAuthClients if you want more than one.  
 *                     Use either this or `oAuthClient` but not both.  
 *                     See {@link FastifyOAuthClient}.
 * - `oAuthResServer`  OAuth resource server.  See 
 *                     {@link FastifyOAuthResourceServer}.
 * 
 * There is also an API key server which is not available as a variable as
 * it has no functions other than the hook it registers.
 * See {@link FastifyApiKeyServer}.
 * 
 * For a list of user-level URLs that can be enabled, and their input and output 
 * requirements, see {@link FastifySessionServer}.  FOr a list of
 * admin endpoints that can be enabled, see {@link FastifyAdminEndpoints}.
 * 
 * **Authenticators**
 * 
 * One and two factor authentication is supported.  Authentication is provided
 * by classes implementing {@link @crossauth/backend!Authenticator}.  They are passed as an 
 * object to this class, keyed on the name that appears in the user record
 * as `factor1` or `factor2`.  
 * 
 * For example, if you have passwords in your user database, you can use
 * {@link @crossauth/backend!LocalPasswordAuthenticator}.  If this method of authentication
 * is called `password` in the `factor1` field of the user record,
 * pass it in the `authenticators` parameter in the constructor with a key
 * of `password`.
 * 
 */
export class FastifyServer {
    private views : string = "views";
    private static isAdminFn: (user : User) => boolean = defaultIsAdminFn;

    /** The Fastify app, which was either passed in the constructor or
     *  created if none was passed in.
     */
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;

    /** See class comment */
    readonly sessionServer? : FastifySessionServer; 

    /** 
     * See class comment
     * 
     * Will be the same as `sessionServer` if that is passed instawd
     */
    readonly sessionAdapter? : FastifySessionAdapter; 

    /** See class comment */
    readonly oAuthAuthServer? : FastifyAuthorizationServer;

    /** See class comment */
    readonly oAuthClient? : FastifyOAuthClient;

    /** See class comment */
    readonly oAuthClients? : FastifyOAuthClient[];

    /** See class comment */
    readonly oAuthResServer? : FastifyOAuthResourceServer;

    /** Config for `@fastify/cors` */
    private cors : {[key:string]:any} | undefined;

    private audience : string = "";

    /**
     * Integrates fastify session, API key and OAuth servers
     * @param config object with entries as follow:
     *     - `session` if passed, instantiate the session server (see class
     *       documentation).  The value is an object with a `keyStorage` field
     *       which must be present and should be the {@link KeyStorage} instance
     *       where session IDs are stored.  A field called `options` whose
     *       value is an {@link FastifySessionServerOptions} may also be
     *       provided.
     *     - `apiKey` if passed, instantiate the session server (see class
     *       documentation).  The value is an object with a `keyStorage` field
     *       which must be present and should be the {@link KeyStorage} instance
     *       where API keys are stored.  A field called `options` whose
     *       value is an {@link FastifyApiKeyServerOptions} may also be
     *       provided.
     *     - `oAuthAuthServer` if passed, instantiate the session server (see class
     *       documentation).  The value is an object with a `keyStorage` field
     *       which must be present and should be the {@link KeyStorage} instance
     *       where authorization codes are stored.  This may be the same as
     *       the table storing session IDs or may be different.  A field
     *       called `clientStorage` with a value of type {@link OAuthClientStorage}
     *       must be provided and is where OAuth client details are stored.
     *       A field called `options` whose
     *       value is an {@link FastifyAuthorizationServerOptions} may also be
     *       provided.
     *     - `oAuthClient` if present, an OAuth client will be created.
     *       There must be a field called `authServerBaseUrl` and is the 
     *       bsae URL for the authorization server.  When validating access
     *       tokens, the `iss` claim must match this.
     *     - `oAuthClients` if present, an array of OAuth clients will be created.
     *       There must be a field called `authServerBaseUrl` and is the 
     *       bsae URL for the authorization serve for each.  When validating access
     *       tokens, the `iss` claim must match this.
     *       Do not use both this and `oAuthClient`.
     *     - `oAuthResServer` if present. an OAuth resource server will be
     *       created.  It has one optional field: `protectedEndpoints`.  The
     *       value is an object whose key is a URL (relative to the base
     *       URL of the application).  The value is an object that contains
     *       one optional parameter: `scope`, a string.  The client/user calling
     *       the endpoint must have authorized this scope to call this endpoint,
     *       otherwise an access denied error is returned. 
     *  @param options application-wide options of type
     *       {@link FastifyServerOptions}.
     *
     */
    constructor({ 
        session,
        sessionAdapter,
        apiKey,
        oAuthAuthServer,
        oAuthClient,
        oAuthClients,
        oAuthResServer } : {
            session?: {
                    keyStorage: KeyStorage, 
                    options?: FastifySessionServerOptions,
                },
            sessionAdapter?: FastifySessionAdapter,
            apiKey?: {
                keyStorage: KeyStorage,
                options? : FastifyApiKeyServerOptions
            },
            oAuthAuthServer? : {
                clientStorage: OAuthClientStorage,
                keyStorage: KeyStorage,
                options? : FastifyAuthorizationServerOptions,
            },
            oAuthClient? : {
                authServerBaseUrl: string,
                options? : FastifyOAuthClientOptions,
            },
            oAuthClients? : {
                authServerBaseUrl: string,
                options? : FastifyOAuthClientOptions,
            }[],
            oAuthResServer? : {
                options? : FastifyOAuthResourceServerOptions,
            }},
            options: FastifyServerOptions = {}) {


        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("cors", ParamType.Json, this, options, "CORS");

        if (options.isAdminFn) FastifyServer.isAdminFn = options.isAdminFn;

        if (options.app) {
            this.app = options.app;
        } else {
            if (this.views) {
                nunjucks.configure(this.views, {
                    autoescape: true,
                });
            }
            this.app = fastify({logger: false});
            this.app.register(view, {
                engine: {
                    nunjucks: nunjucks,
                },
                templates: [
                    "node_modules/shared-components",
                    this.views,
                ],
                });


        }

        if (this.cors) {
            this.app.register(cors, this.cors);      
        }

        this.app.addContentTypeParser('text/json',
            { parseAs: 'string' },
            this.app.getDefaultJsonParser('ignore', 'ignore'))
        this.app.register(fastifyFormBody);
        this.app.register(cookie, {
            // secret: "my-secret", // for cookies signature
            parseOptions: {}     // options for parsing cookies
          } as FastifyCookieOptions)

        this.app.decorateRequest('user', undefined);
        this.app.decorateRequest('csrfToken', undefined);

        let authenticators : {[key:string]: Authenticator} = {};
        if (options.authenticators) authenticators = options.authenticators; 

        if (session) { 
            if (!authenticators) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "If using session management, must also supply authenticators");
            }
            const sessionServer = new FastifySessionServer(this.app,
                session.keyStorage,
                authenticators,
                { ...options, ...session.options });
            this.sessionServer = sessionServer; 
            this.sessionAdapter = this.sessionServer;
        } else if (sessionAdapter) {
            this.sessionAdapter = sessionAdapter;

        }

        if (apiKey) {
            if (!options.userStorage) throw new CrossauthError(ErrorCode.Configuration, "Need a user storage to user API server");
            new FastifyApiKeyServer(this.app,
                options.userStorage,
                apiKey.keyStorage,
                { ...options, ...apiKey.options });
        }

        if (oAuthAuthServer) 
        {
            let extraOptions : FastifyAuthorizationServerOptions = {};
            if (this.sessionServer) extraOptions.loginUrl = this.sessionServer.prefix + "login";
            this.oAuthAuthServer = new FastifyAuthorizationServer(this.app,
                this,
                oAuthAuthServer.clientStorage,
                oAuthAuthServer.keyStorage,
                authenticators,
                { ...extraOptions, ...options, ...oAuthAuthServer.options });
        }

        if (oAuthClient && this.oAuthClients) {
            throw new CrossauthError(ErrorCode.Configuration, "Do not use both oAuthClient and oAuthClients")
        }
        if (oAuthClient) {
            this.oAuthClient = new FastifyOAuthClient(this,
                oAuthClient.authServerBaseUrl,
                { ...options, ...oAuthClient.options });
        }
        if (oAuthClients) {
            this.oAuthClients = [];
            for (let client of oAuthClients) {
                this.oAuthClients.push(
                    new FastifyOAuthClient(this,
                        client.authServerBaseUrl,
                        { ...options, ...client.options })
                );
            }
        }

        if (oAuthResServer) {
            this.audience = ""
            setParameter("audience", ParamType.String, this, options, "OAUTH_AUDIENCE", true);
            this.oAuthResServer = new FastifyOAuthResourceServer(this.app, 
                [new OAuthTokenConsumer(this.audience, options)],
                {sessionAdapter: this.sessionAdapter, ...oAuthResServer.options, ...options}
            )
        }
    }

    /**
     * This is a convenience function that just wraps
     * {@link FastifySessionServer.validateCsrfToken}.
     * @param request the fastify request
     * @returns a string of the CSRF cookie value or undefined if it
     * is not valid. 
     */
    validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) 
    : string|undefined {
        if (!this.sessionServer) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Cannot validate csrf tokens if sessions not enabled");
        }
        return this.sessionServer.validateCsrfToken(request);
    }

    /**
     * Calls the passed error function passed if the CSRF
     * token in the request is invalid.  
     * 
     * Use this to require a CSRF token in your endpoints.
     * 
     * @param request the Fastify request
     * @param reply the Fastify reply object
     * @param errorFn the error function to call if the CSRF token is invalid
     * @returns if no error, returns an object with `error` set to false and
     * `reply` set to the passed reply object.  Otherwise returns the reply
     * from calling `errorFn`.
     */
    async errorIfCsrfInvalid(request: FastifyRequest<{ Body: CsrfBodyType }>,
        reply: FastifyReply,
        errorFn?: FastifyErrorFn)
        : Promise<{ reply: FastifyReply, error: boolean }> {
        try {
            //this.validateCsrfToken(request);
            if (!request.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf)
            return {error: false, reply};
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.warn(j({
                msg: `Attempt to access url without csrf token`,
                url: request.url
            }));
            try {
                if (errorFn) {
                    const ce = CrossauthError.asCrossauthError(e);
                    return {error: true, reply: await errorFn(this, request, reply, ce)};
                } else if (this.sessionServer?.errorPage) {
                    const ce = new CrossauthError(ErrorCode.InvalidCsrf, "CSRF Token not provided")
                    return {error: true, reply: reply.status(401)
                        .view(this.sessionServer?.errorPage??"",
                        {
                            errorMessage: ce.message,
                            errorMessages: ce.messages,
                            status: ce.httpStatus,
                            errorCode: ErrorCode.InvalidCsrf,
                            errorCodeName: ErrorCode[ErrorCode.InvalidCsrf]
                        })};
                }
            } catch (e2) {
                CrossauthLogger.logger.error(j({err: e2}));
                return {error: true, reply: reply.status(401).send(ERROR_401)};                
            }
            return {error: true, reply: reply.status(401).send(ERROR_401)};
        }
    }

    /**
     * Calls the passed error function passed if the user is not logged in.
     * 
     * Use this to password protect endpoints. 
     * 
     * @param request the Fastify request
     * @param reply the Fastify reply object
     * @param errorFn the error function to call if the user is not logged in.
     * @returns if no error, returns an object with `error` set to false and
     * `reply` set to the passed reply object.  Otherwise returns the reply
     * from calling `errorFn`.
     */
    async errorIfNotLoggedIn(request: FastifyRequest<{ Body: CsrfBodyType }>,
        reply: FastifyReply,
        errorFn?: FastifyErrorFn) : Promise<FastifyReply|undefined> {
        if (!request.user) {
            CrossauthLogger.logger.warn(j({
                msg: `Attempt to access url without csrf token`,
                url: request.url
            }));
            try {
                if (errorFn) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, 
                        "User is not logged in");
                    return await errorFn(this, request, reply, ce);
                } else if (this.sessionServer?.errorPage) {
                    return reply.status(401).view(this.sessionServer?.errorPage??"",
                        {
                            errorMessage: "User is not logged in",
                            status: 401,
                            code: ErrorCode.Unauthorized,
                            codeName: ErrorCode[ErrorCode.Unauthorized]});
                }
            } catch (e2) {
                CrossauthLogger.logger.debug(j({err: e2}));
                CrossauthLogger.logger.error(j({
                    cerr: e2,
                    hashedSessionCookie: this.sessionServer?.getHashOfSessionId(request)
                }));
                return reply.status(401).send(ERROR_401);                
            }
            return reply.status(401).send(ERROR_401);
        }
    }

    /**
     * Sends a reply by rendering the `errorPage` if present, or a standard
     * error page if it isn't.
     * 
     * The renderer configured for the reply object is called (Nunjucks
     * by default) with the following data parameters:
     * - `errorCode` See {@link @crossauth/common!ErrorCode}.
     * - `errorCodeName` the text version of `errorCode`.
     * - `msg` the error message
     * - `httpStatus` the HTTP status code.
     * 
     * @param reply the Fastify reply object
     * @param status the HTTP status code to return
     * @param errorPage the error page to render.
     * @param error an error message string.  Ignored if `e` is defined.
     * @param e optionall, an exception.  This will be logged and the message
     *          will be sent to the error page.
     * @returns the reply from rendering the error page.
     * 
     */
    static sendPageError(reply: FastifyReply,
        status: number,
        errorPage?: string,
        error?: string,
        e?: any) {
        if (!error || !e) {
            CrossauthLogger.logger.warn(j({
                msg: error,
                errorCode: ErrorCode.UnknownError,
                errorCodeName: ErrorCode[ErrorCode.UnknownError],
                httpStatus: status
            }));
            if (errorPage) {
                return reply.status(status).view(errorPage,
                    { status: status, 
                        errorCodeName: ErrorCode[ErrorCode.UnknownError] });
            } else {
                return reply.status(status)
                .send(status==401 ? ERROR_401 : ERROR_500);
            }
        }
        try {
            let code = 0;
            let codeName = "UnknownError";
            if ("isCrossAuthError" in e) {
                const ce = CrossauthError.asCrossauthError(e);
                code = ce.code;
                codeName = ce.name;
                if (!error) error = e.message;
            }
            if (!error) {
                if (status == 401) {
                    error = "You are not authorized to access this page";
                    code = ErrorCode.Unauthorized;
                    codeName = ErrorCode[code];
                } else if (status == 403) {
                    error = "You do not have permission to access this page";
                    code = ErrorCode.Forbidden;
                    codeName = ErrorCode[code];
                } else {
                    error = "An unknwon error has occurred"
                }
            }         
            CrossauthLogger.logger.warn(j({
                msg: error,
                errorCode: code,
                errorCodeName: codeName,
                httpStatus: status
            }));
            if (errorPage) {
                return reply.status(status).view(errorPage,
                    {
                        status: status,
                        errorMessage: error,
                        errorCode: code,
                        errorCodeName: codeName });
            } else {
                return reply.status(status)
                .send(status==401 ? ERROR_401 : ERROR_500);
            }
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return reply.status(status)
            .send(status==401 ? ERROR_401 : ERROR_500);

        }
    }    

    /*
     * Gets the sessin key from the request or undefined if there isn't one.
     * @param request the Fastify request
     * @returns the session key or undefined
     */
    /*async getSessionKey(request : FastifyRequest) : Promise<Key|undefined> {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot update session data if sessions not enabled");
       return  await this.sessionServer.getSessionKey(request);
    }*/

    /**
     * Creates a session ID but not associated with a user in the database.
     * 
     * This is useful for tracking data between requests before a user
     * has logged in
     * @param request the Fastify request
     * @param reply the Fastify reply
     * @param data data to put in the sesion's `data` field.
     * @returns the new session cookie value.
     */
    async createAnonymousSession(request: FastifyRequest,
        reply: FastifyReply,
        data?: { [key: string]: any }) : Promise<string>  {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, 
            "Sessions not enabled");
        CrossauthLogger.logger.debug(j({msg: "Creating anonymous session"}));
        return await this.sessionServer.createAnonymousSession(request, reply, data);
    }

    /**
     * Calls the `isAdminFn` passed during construction.
     * @param user the user to check
     * @returns true if the passed user is an admin, false otherwise.
     */
    static isAdmin(user : User) { return FastifyServer.isAdminFn(user); }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(j({
                msg: "Starting fastify server",
                port: port
        })),
        );

    }

    /**
     * Returns a hash of the session ID.  Used for logging (for security,
     * the actual session ID is not logged)
     * @param request the Fastify request
     * @returns hash of the session ID
     */
    getHashOfSessionId(request : FastifyRequest) : string {
        if (!request.sessionId) return "";
        try {
            return Crypto.hash(request.sessionId);
        } catch (e) {}
        return "";
    }
}
