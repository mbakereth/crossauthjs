import fastify, { FastifyInstance, FastifyRequest } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from '../storage';
import { Authenticator } from '../auth';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import { FastifySessionServer } from './fastifysession';
import type { FastifySessionServerOptions, CsrfBodyType } from './fastifysession';
import { ApiKeyManager } from '../apikey';
import { FastifyApiKeyServer, FastifyApiKeyServerOptions } from './fastifyapikey';


/**
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifyServerOptions extends FastifySessionServerOptions, FastifyApiKeyServerOptions {

    /** You can pass your own fastify instance or omit this, in which case Crossauth will create one */
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,

    /** List of endpoints to add to the server ("login", "api/login", etc, prefixed by the `prefix` parameter.  Empty for all.  Default all. */
    endpoints? : string,
}


/**
 * Endpoints that depend on sessions being enabled and display HTML
 */
export const SessionPageEndpoints = [
    "login",
    "logout",
    "changepassword",
    "updateuser",
];

/**
 * API (JSON) endpoints that depend on sessions being enabled 
 */
export const SessionApiEndpoints = [
    "api/login",
    "api/logout",
    "api/changepassword",
    "api/userforsessionkey",
    "api/getcsrftoken",
    "api/updateuser",
];

/**
 * API (JSON) endpoints that depend on 2FA being enabled 
 */
export const Factor2ApiEndpoints = [
    "api/configurefactor2",
    "api/loginfactor2",
    "api/changefactor2",
    "api/factor2",
    "api/cancelfactor2",
];

/**
 * Endpoints that depend on email verification being enabled and display HTML
 */
export const EmailVerificationPageEndpoints = [
    "verifyemail",
    "emailverified",
];

/**
 * API (JSON) endpoints that depend on email verification being enabled 
 */
export const EmailVerificationApiEndpoints = [
    "api/verifyemail",
];

/**
 * Endpoints that depend on password reset being enabled and display HTML
 */
export const PasswordResetPageEndpoints = [
    "requestpasswordreset",
    "resetpassword",
];

/**
 * API (JSON) endpoints that depend on password reset being enabled 
 */
export const PasswordResetApiEndpoints = [
    "api/requestpasswordreset",
    "api/resetpassword",
];

/**
 * Endpoints for signing a user up that display HTML
 */
export const SignupPageEndpoints = [
    "signup",
]

/**
 * API (JSON) endpoints for signing a user up that display HTML
 */
export const SignupApiEndpoints = [
    "api/signup",
]

/**
 * Endpoints for signing a user up that display HTML
 */
export const Factor2PageEndpoints = [
    "configurefactor2",
    "loginfactor2",
    "changefactor2",
    "factor2",
]

/**
 * These are all the endpoints created by default by this server-
 */
export const AllEndpoints = [
    ...SignupPageEndpoints,
    ...SignupApiEndpoints,
    ...SessionPageEndpoints,
    ...SessionApiEndpoints,
    ...EmailVerificationPageEndpoints,
    ...EmailVerificationApiEndpoints,
    ...PasswordResetPageEndpoints,
    ...PasswordResetApiEndpoints,
    ...Factor2PageEndpoints,
    ...Factor2ApiEndpoints,
];


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
    private prefix : string = "/";
    private endpoints : string[] = [];
    // @ts-ignore
    private sessionServer? : FastifySessionServer; // only needed for testing

    private enableEmailVerification : boolean = false;
    private enablePasswordReset : boolean = true;
    private allowedFactor2 : string[] = [];


    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param optoions see {@link FastifyServerOptions}
     */
    constructor(userStorage: UserStorage, {session, apiKey} : {
                session?: {
                    keyStorage: KeyStorage, 
                    authenticators: {[key:string]: Authenticator}, 
                },
                apiKey?: {keyStorage: KeyStorage},
                },
                options: FastifyServerOptions = {}) {


        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("enableSessions", ParamType.Boolean, this, options, "ENABLE_SESSIONS");
        setParameter("enableapiKeys", ParamType.Boolean, this, options, "ENABLE_APIKEYS");
        setParameter("allowedFactor2", ParamType.StringArray, this, options, "ALLOWED_FACTOR2");
        setParameter("enableEmailVerification", ParamType.Boolean, this, options, "ENABLE_EMAIL_VERIFICATION");
        setParameter("enablePasswordReset", ParamType.Boolean, this, options, "ENABLE_PASSWORD_RESET");

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

        if (session) 
        {
            this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
            this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
            if (this.enableEmailVerification) this.endpoints = [...this.endpoints, ...EmailVerificationPageEndpoints, ...EmailVerificationApiEndpoints];
            if (this.enablePasswordReset) this.endpoints = [...this.endpoints, ...PasswordResetPageEndpoints, ...PasswordResetApiEndpoints];
            if (this.allowedFactor2.length > 0) this.endpoints = [...this.endpoints, ...Factor2PageEndpoints, ...Factor2ApiEndpoints];
        }
        setParameter("endpoints", ParamType.StringArray, this, options, "ENDPOINTS");

        if (session) { 
            const sessionServer = new FastifySessionServer(this.app, this.prefix, userStorage, session.keyStorage, session.authenticators, options);
            this.sessionServer = sessionServer; // for testing only
            sessionServer.addEndpoints(this.endpoints);
        }

        if (apiKey) {
            new FastifyApiKeyServer(this.app, userStorage, apiKey.keyStorage, options);
        }
    }
    
    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>) {
        if (!this.sessionServer) {
            throw new CrossauthError(ErrorCode.Configuration, "Cannot validate csrf tokens if sessions not enabled");
        }
        return this.sessionServer.validateCsrfToken(request);
    }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(j({msg: "Starting fastify server", port: port, prefix: this.prefix})),
        );

    }
}
