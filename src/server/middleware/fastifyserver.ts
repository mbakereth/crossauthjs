import fastify, { FastifyInstance } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { UserStorage, KeyStorage } from '../storage';
import { Authenticator } from '../auth';
import { CrossauthError, ErrorCode } from "../..";
import { CrossauthLogger, j } from '../..';
import { setParameter, ParamType } from '../utils';
import { FastifySessionServer, type FastifySessionServerOptions } from './fastifysession';



/**
 * Options for {@link FastifyServer }.
 * 
 * See {@link FastifyServer } constructor for description of parameters
 */
export interface FastifyServerOptions extends FastifySessionServerOptions {

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
export const TwoFactorApiEndpoints = [
    "api/signuptwofactor",
    "api/logintwofactor",
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
export const TwoFactorPageEndpoints = [
    "signuptwofactor",
    "logintwofactor"
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
    ...TwoFactorPageEndpoints,
    ...TwoFactorApiEndpoints,
];


/**
 * This class provides a complete (but without HTML files) auth backend server with endpoints served using 
 * Fastify.
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
 * **Endpoints provided**
 * 
 * All POST methods also take a csrfToken.  If user is logged in or anonymous sessions are enabled.
 * 
 * All POST methods are passed user, csrfToken, code, error and errors.
 * this is checked.
 * 
 * | METHOD | ENDPOINT                   | PATH PARAMS | GET/BODY PARAMS                          | VARIABLES PASSED         | FILE               |
 * | ------ | -------------------------- | ----------- | ---------------------------------------- | ------------------------ | ------------------ |
 * | GET    | /login                     |             | next                                     |                          | loginPage          | 
 * | POST   | /login                     |             | next, username, password                 | request params, message  | loginPage          | 
 * | POST   | /api/login                 |             | next, username, password                 |                          |                    | 
 * | POST   | /logout                    |             | next                                     |                          |                    | 
 * | POST   | /api/logout                |             | next                                     |                          |                    | 
 * | GET    | /signup                    |             | next                                     |                          | signupPage         |
 * | POST   | /signup                    |             | next, username, password, user/*         | request params, message  | signupPage         | 
 * | GET    | /changepassword            |             |                                          |                          | changePasswordPage | 
 * | POST   | /changepassword            |             | oldPassword, newPassword, repeatPassword | request params, message  | changePasswordPage | 
 * | POST   | /api/changepassword        |             | oldPassword, newPassword                 |                          |                    | 
 * | GET    | /updateuser                |             |                                          |                          | changePasswordPage | 
 * | POST   | /updateuser                |             | user_*                                   | request params, message  | changePasswordPage | 
 * | POST   | /api/updateuser            |             | user_*                                   |                          |                    | 
 * | GET    | /requestpasswordreset      |             |                                          |                          | changePasswordPage | 
 * | POST   | /requestpasswordreset      |             | email                                    | email, message           | changePasswordPage | 
 * | POST   | /api/requestpasswordreset  |             | password                                 |                          |                    | 
 * | GET    | /resetpassword             | token       |                                          |                          | changePasswordPage | 
 * | POST   | /resetpassword             |             | token, password, repeatPassword          | request params, message  | changePasswordPage | 
 * | POST   | /api/resetpassword         |             | token, password                          |                          |                    | 
 * | GET    | /verifyemail               |  token      |                                          |                          | emailVerifiedPage  | 
 * | GET    | /verifyemail               |  token      |                                          |                          | emailVerifiedPage  | 
 * | GET    | /api/userforsessionkey     |             |                                          |                          |                    | 
 * | GET    | /api/getcsrctoken          |             |                                          |                          |                    | 
 * 
 * If you have fields other than `id`, `username` and `password` in your user table, add them in 
 * `extraFields` when you create your {@link UserStorage} object.  In your signup and user update pages
 * (`signupPage`, `updateUserPage`), prefix these with `user_` in field names and they will be passed
 * into the user object when processing the form.  If there is an error processing the form, they will
 * be back as psot parameters, again prefixed with `user_`.
 * 
 *  **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create
 * and pass in your own Fastify app.
 */
export class FastifyServer {
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private enableSessions : boolean = true;
    private views : string = "views";
    private prefix : string = "/";
    private endpoints : string[] = [];
    // @ts-ignore
    private sessionServer? : FastifySessionServer; // only needed for testing

    private enableEmailVerification : boolean = true;
    private enablePasswordReset : boolean = true;
    private twoFactorRequired :  "off" | "all" | "peruser" = "off";

    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param optoions see {@link FastifyServerOptions}
     */
    constructor(userStorage: UserStorage, 
                keyStorage: KeyStorage, 
                authenticators: {[key:string]: Authenticator}, 
                options: FastifyServerOptions = {}) {

        setParameter("views", ParamType.String, this, options, "VIEWS");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        setParameter("enableSessions", ParamType.Boolean, this, options, "ENABLE_SESSIONS");
        setParameter("twoFactorRequired", ParamType.String, this, options, "TWOFACTOR_REQUIRED");
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
                                
        this.endpoints = [...SignupPageEndpoints, ...SignupApiEndpoints];
        if (this.enableSessions) this.endpoints = [...this.endpoints, ...SessionPageEndpoints, ...SessionApiEndpoints];
        if (this.enableEmailVerification) this.endpoints = [...this.endpoints, ...EmailVerificationPageEndpoints, ...EmailVerificationApiEndpoints];
        if (this.enablePasswordReset) this.endpoints = [...this.endpoints, ...PasswordResetPageEndpoints, ...PasswordResetApiEndpoints];
        if (this.twoFactorRequired != "off") this.endpoints = [...this.endpoints, ...TwoFactorPageEndpoints, ...TwoFactorApiEndpoints];
        setParameter("endpoints", ParamType.StringArray, this, options, "ENDPOINTS");

        // validates the session id and csrftokens, creating if necessary and putting the csrf token
        // and user in the request object.
        if (this.enableSessions) { 
            const sessionServer = new FastifySessionServer(this.app, this.prefix, userStorage, keyStorage, authenticators, options);
            this.sessionServer = sessionServer; // for testing only
            if (this.endpoints.includes("login")) {
                sessionServer.addLoginEndpoints();
            }

            if (this.endpoints.includes("logintwofactor")) {
                sessionServer.addLoginTwoFactorEndpoints();
            }
    
            if (this.endpoints.includes("signup")) {
                sessionServer.addSignupEndpoints();
            }

            if (this.endpoints.includes("signuptwofactor")) {
                sessionServer.addSignupTwoFactorEndpoints();
            }

            if (this.endpoints.includes("changepassword")) {
                sessionServer.addChangePasswordEndpoints();
            }

            if (this.endpoints.includes("updateuser")) {
                sessionServer.addUpdateUserEndpoints();
            }

            if (this.endpoints.includes("requestpasswordreset")) {
                sessionServer.addRequestPasswordResetENdpoints();
            }
    
            if (this.endpoints.includes("resetpassword")) {
                if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /resetpassword");
                sessionServer.addResetPasswordEndpoints();
            }

            if (this.endpoints.includes("verifyemail")) {
                if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification  must be enabled for /verifyemail");
                sessionServer.addVerifyEmailEndpoints();
            }
    
            if (this.endpoints.includes("logout")) {
                sessionServer.addLogoutEndpoints();
    
            }
            if (this.endpoints.includes("api/login")) {
                sessionServer.addApiLoginEndpoints();
            }
    
            if (this.endpoints.includes("api/logintwofactor")) {
                sessionServer.addApiLoginTwoFactorEndpoints();
            }
          
            if (this.endpoints.includes("api/logout")) {
                sessionServer.addApiLogoutEndpoints();
            }

            if (this.endpoints.includes("api/signup")) {
                sessionServer.addApiSignupEndpoints();
            }

            if (this.endpoints.includes("api/signuptwofactor")) {
                sessionServer.addApiSignupTwoFactorEndpoints();
            }

            if (this.endpoints.includes("api/changepassword")) {
                sessionServer.addApiChangePasswordEndpoints();
            }

            if (this.endpoints.includes("api/updateuser")) {
                sessionServer.addApiUpdateUserEndpoints();
            }

            if (this.endpoints.includes("api/resetpassword")) {
                if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/resetpassword");
                sessionServer.addApiResetPasswordEndpoints();
            }

            if (this.endpoints.includes("api/requestpasswordreset")) {
                if (!this.enablePasswordReset) throw new CrossauthError(ErrorCode.Configuration, "Password reset must be enabled for /api/requestpasswordreset");
                sessionServer.addApiRequestPasswordResetEndpoints();
            }

            if (this.endpoints.includes("api/verifyemail")) {
                if (!this.enableEmailVerification) throw new CrossauthError(ErrorCode.Configuration, "Email verification must be enabled for /api/verifyemail");
                sessionServer.addApiVerifyEmailEndpoints();
            }

            if (this.endpoints.includes("api/userforsessionkey")) {
                sessionServer.addApiUserForSessionKeyEndpoints();
            }

            if (this.endpoints.includes("api/getcsrftoken")) {
                sessionServer.addApiGetCsrfTokenEndpoints();
        
            }
        }
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
