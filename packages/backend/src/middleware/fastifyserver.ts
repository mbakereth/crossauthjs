import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage, OAuthClientStorage } from '../storage';
import { Authenticator } from '../auth';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import { FastifySessionServer } from './fastifysession';
import type { FastifySessionServerOptions, CsrfBodyType } from './fastifysession';
import { ApiKeyManager } from '../apikey';
import { FastifyApiKeyServer, FastifyApiKeyServerOptions } from './fastifyapikey';
import { FastifyAuthorizationServer, type FastifyAuthorizationServerOptions } from './fastifyoauthserver';
import { FastifyOAuthClient, type FastifyOAuthClientOptions } from './fastifyoauthclient';
import { FastifyOAuthResourceServer, type FastifyOAuthResourceServerOptions } from './fastifyresserver';
import { Key } from '@crossauth/common';

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
export interface FastifyServerOptions extends FastifySessionServerOptions, FastifyApiKeyServerOptions, FastifyAuthorizationServerOptions, FastifyOAuthClientOptions, FastifyOAuthResourceServerOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** If this is passed, it is registered as a Nunjucks view folder with autoscape on */
    views? : string,
};

export type FastifyErrorFn = (server: FastifyServer, request : FastifyRequest, reply : FastifyReply, ce : CrossauthError) => Promise<FastifyReply>;

/**
 * This class provides a complete (but without HTML files) auth backend server for
 * Fastify applications
 * 
 * If you do not pass an Fastify app to this class, it will create one.  By default, pages are rendered
 * with Nunjucks.  If you prefer another renderer that is compatible with Fastify, create your
 * own Fastify app and configure the renderer using @fastify/view.
 * 
 * By default, all views are expected to be in a directory called `views` relative to the directory the
 * server is started in.  This can be overwritten by setting the `views` option.
 * 
 * Note that `views`, and the Nunjucls pages are not used by the API endpoints (those starting in /api).
 * 
 *  **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create
 * and pass in your own Fastify app.
 * 
 * For session management, see {@link FastifySession}.
 * For API key management, see {@link ApiKeyManager}
 */
export class FastifyServer {
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private views : string = "views";
    readonly sessionServer? : FastifySessionServer; 
    readonly oAuthAuthServer? : FastifyAuthorizationServer;
    readonly oAuthClient? : FastifyOAuthClient;
    readonly oAuthResServer? : FastifyOAuthResourceServer;

    /**
     * Integrates fastify session, API key and OAuth servers
     * @param options see {@link FastifyServerOptions}
     */
    constructor(userStorage: UserStorage, {session, apiKey, oAuthAuthServer, oAuthClient, oAuthResServer} : {
                session?: {
                    keyStorage: KeyStorage, 
                    authenticators: {[key:string]: Authenticator}, 
                    options?: FastifySessionServerOptions,
                },
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
                    authServerBaseUri: string,
                    options? : FastifyOAuthClientOptions,
                },
                oAuthResServer? : {
                    protectedEndpoints?: {[key:string]: {scope? : string}},
                }},
                options: FastifyServerOptions = {}) {


        setParameter("views", ParamType.String, this, options, "VIEWS");

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

        this.app.addContentTypeParser('text/json', { parseAs: 'string' }, this.app.getDefaultJsonParser('ignore', 'ignore'))
        this.app.register(fastifyFormBody);
        this.app.register(cookie, {
            // secret: "my-secret", // for cookies signature
            parseOptions: {}     // options for parsing cookies
          } as FastifyCookieOptions)

        this.app.decorateRequest('user', undefined);
        this.app.decorateRequest('csrfToken', undefined);

        if (session) { 
            const sessionServer = new FastifySessionServer(this.app, userStorage, session.keyStorage, session.authenticators, {...options, ...session.options});
            this.sessionServer = sessionServer; // for testing only
        }

        if (apiKey) {
            new FastifyApiKeyServer(this.app, userStorage, apiKey.keyStorage, {...options, ...apiKey.options});
        }

        if (oAuthAuthServer) 
        {
            let extraOptions : FastifyAuthorizationServerOptions = {};
            if (this.sessionServer) extraOptions.loginUrl = this.sessionServer.prefix + "login";
            this.oAuthAuthServer = new FastifyAuthorizationServer(this.app, this, oAuthAuthServer.clientStorage, oAuthAuthServer.keyStorage, {...extraOptions, ...options, ...oAuthAuthServer.options});
        }

        if (oAuthClient) {
            this.oAuthClient = new FastifyOAuthClient(this, oAuthClient.authServerBaseUri, {...options, ...oAuthClient.options});
        }

        if (oAuthResServer) {
            this.oAuthResServer = new FastifyOAuthResourceServer(this.app, 
                this.oAuthAuthServer,
                oAuthResServer.protectedEndpoints, options
            )
        }
    }

    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) : Promise<string|undefined>{
        if (!this.sessionServer) {
            throw new CrossauthError(ErrorCode.Configuration, "Cannot validate csrf tokens if sessions not enabled");
        }
        return this.sessionServer.validateCsrfToken(request);
    }

    async errorIfCsrfInvalid(request : FastifyRequest<{ Body: CsrfBodyType }>, reply : FastifyReply, errorFn? : FastifyErrorFn) : Promise<FastifyReply|undefined> {
        try {
            await this.validateCsrfToken(request)
            return undefined;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.warn(j({msg: `Attempt to access url without csrf token`, url: request.url}));
            try {
                if (errorFn) {
                    const errorCode = ErrorCode.UnknownError;
                    const errorMessage = (e instanceof Error) ? e.message : "Unknown error";
                    const ce = (e instanceof CrossauthError) ? e as CrossauthError : new CrossauthError(errorCode, errorMessage);
                    return errorFn(this, request, reply, ce);
                } else if (this.sessionServer?.errorPage) {
                    return reply.status(401).view(this.sessionServer?.errorPage??"",
                        {errorMessage: "CSRF Token not provided", status: 401, code: ErrorCode.InvalidCsrf, codeName: ErrorCode[ErrorCode.InvalidCsrf]});
                }
            } catch (e2) {
                CrossauthLogger.logger.error(j({err: e2}));
                return reply.status(401).send(ERROR_401);                
            }
            return reply.status(401).send(ERROR_401);
        }
    }

    async errorIfNotLoggedIn(request : FastifyRequest<{ Body: CsrfBodyType }>, reply : FastifyReply, errorFn? : FastifyErrorFn) : Promise<FastifyReply|undefined> {
        if (!request.user) {
            CrossauthLogger.logger.warn(j({msg: `Attempt to access url without csrf token`, url: request.url}));
            try {
                if (errorFn) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "User is not logged in");
                    return errorFn(this, request, reply, ce);
                } else if (this.sessionServer?.errorPage) {
                    return reply.status(401).view(this.sessionServer?.errorPage??"",
                        {errorMessage: "User is not logged in", status: 401, code: ErrorCode.Unauthorized, codeName: ErrorCode[ErrorCode.Unauthorized]});
                }
            } catch (e2) {
                CrossauthLogger.logger.debug(j({err: e2}));
                CrossauthLogger.logger.error(j({cerr: e2, hashedSessionCookie: this.sessionServer?.getHashOfSessionCookie(request)}))
                return reply.status(401).send(ERROR_401);                
            }
            return reply.status(401).send(ERROR_401);
        }
    }

    static sendPageError(reply : FastifyReply, status : number, errorPage? : string, error?: string, e? : any) {
        let code = 0;
        let codeName = "UnknownError";
        if (e instanceof CrossauthError) {
            code = e.code;
            codeName = ErrorCode[code];
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
        CrossauthLogger.logger.warn(j({msg: error, errorCode: code, errorCodeName: codeName, httpStatus: status}));
        if (errorPage) {
            return reply.status(status).view(errorPage, {status: status, errorMessage: error, errorCode: code, errorCodeName: codeName});
        } else {
            return reply.status(status).send(status==401 ? ERROR_401 : ERROR_500);
        }
    }

    async updateSessionData(request : FastifyRequest, name : string, value : {[key:string]:any}) {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled");
        await this.sessionServer.updateSessionData(request, name, value);
    }

    async getSessionData(request : FastifyRequest, name : string, ) : Promise<{[key:string]:any}|undefined> {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled");
       return  await this.sessionServer.getSessionData(request, name);
    }

    async getSessionKey(request : FastifyRequest) : Promise<Key|undefined> {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled");
       return  await this.sessionServer.getSessionKey(request);
    }

    getSessionCookieValue(request : FastifyRequest) : string|undefined {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled");
        return  this.sessionServer.getSessionCookieValue(request);
    }

    async createAnonymousSession(request : FastifyRequest, reply : FastifyReply, data? : {[key:string]:any}) : Promise<string>  {
        if (!this.sessionServer) throw new CrossauthError(ErrorCode.Configuration, "Sessions not enabled");
        CrossauthLogger.logger.debug(j({msg: "Creating anonymous session"}));
        return await this.sessionServer.createAnonymousSession(request, reply, data);
    }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(j({msg: "Starting fastify server", port: port})),
        );

    }
}
