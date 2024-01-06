import fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import view from '@fastify/view';
import fastifyFormBody from '@fastify/formbody';
import type { FastifyCookieOptions } from '@fastify/cookie'
import cookie from '@fastify/cookie'
import { Server, IncomingMessage, ServerResponse } from 'http'

import nunjucks from "nunjucks";
import { CookieSessionManager, Cookie } from './cookieauth';
import { CrossauthError, ErrorCode } from "..";
import { User } from '../interfaces';
import { CrossauthLogger } from '..';

const CSRFHEADER = "X-CROSSAUTH-CSRF";

/**
 * Options for {@link FastifyCookieAuthServer }.
 * 
 * See {@link FastifyCookieAuthServer } constructor for description of parameters
 */
export interface FastifyCookieAuthServerOptions {
    app? : FastifyInstance<Server, IncomingMessage, ServerResponse>,
    prefix? : string,
    loginRedirect? : string;
    logoutRedirect? : string;
    views? : string;
    loginPage? : string;
    errorPage? : string;
    anonymousSessions? : boolean,
    keepAnonymousSessionId? : false,
}

interface LoginBodyType {
    username: string;
    password: string;
    next? : string;
    csrfToken: string;
}

interface CsrfBodyType {
    csrfToken : string;
}

interface LoginParamsType {
    next? : string;
}

  /**
 * This class provides a complete (but without HTML files) auth backend server with endpoints served using Fastify.
 * 
 * If you do not pass an Fastify app to this class, it will create one.  If you set the views parameter, it
 * will also configure Nunjucks as the template engine for the login and error pages.
 * 
 * To use Nunjucks views, set the `views` option in the constructor to the directory containing the views files.
 * When running through Node, this will be relative to the directory it is run from, eg `views`.  
 * If in a web browser, it should be a URL, eg `/views`.
 * 
 * If setting `views`, you should also set `loginPage` and `errorPage` to the Nunjucks templates for the 
 * login and error pages respectively.  If you do not set `loginPage`, there will be no GET `/login` endpoint.
 * Failed login attempts will be directed to the `errorPage`.
 * 
 * If you do not set `errorPage` and there is an error or failed login, a bare bones error page will be displyed.
 * 
 * Note that `views`, `loginPage` and `errorPage` are used only by the `/login` and `/logout` endpoints.  The
 * `/api/*` endpoints only return JSON.
 * 
 * **Endpoints provided**
 * 
 *    * GET `/login` : Only provided if `views` and `loginPage` have been set.  Renders your login page.  
 *      If there was an authentication error, this page is also rendered with `error` set to the error message
 *      (display it with `{{ error }}` in your template).
 *    * POST `/login` : processes a login.  Reads `username` and `password` from the POST parameters or JSON body.
 *      If the credentials are valid, sets a session ID cookie and sends a redirect to `loginRedirect` 
 *      (or to `/` if this wasn't set).  If there is an error, the `loginPage` is rendered with `error` set to 
 *      the error message (see GET `/login`) above.  IF `loginPage` is not set, the `errorPage` is rendered
 *      instead.  If this is also not set, a bare bones error page is displayeds.
 *    * POST `/api/login` takes the same parameters as POST `/login` but returns a JSON string, both upon success
 *      or failure.  If login was successful, this will be `{status: "ok"}` and the session cookie will also be
 *      sent.  If login was not successful, it will be `{"status; "error", error: message, code: code}` where
 *      code is in {@link index!ErrorCode }.
 *    * POST `/api/logout` logs a ser out, ie deletes the session key given in the cookie 
 *      and clears the cookie.  It returns `{status: "ok"}`  
 *      or  `{"status; "error", error: message, code: code}` if there was an error.
 *    * GET `/api/userforsessionke` takes the session ID in the cookie and returns the user associated with it.
 *      Returns `{status: "ok"}` or  `{"status; "error", error: message, code: code}` if there was an error.
 * 
 *    **Using your own Fastify app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create and
 * pass in your own Fastify app.
 */
export class FastifyCookieAuthServer {
    readonly app : FastifyInstance<Server, IncomingMessage, ServerResponse>;
    private prefix : string;
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
    private loginPage? : string;
    private errorPage? : string;
    private sessionManager : CookieSessionManager;
    private anonymousSessions = true;
    private keepAnonymousSessionId = false;

    /**
     * Creates the Fastify endpoints, optionally also the Fastify app.
     * @param sessionManager an instance of {@link CookieSessionManager }.  The endpoints are just wrappers
     *                       around this, adding the HTTP interaction.
     * @param app you can pass your own Fastify instance.  A separate router will be added for the endpoints.  
     *            If you do not pass one, an instance will be created, with Nunjucks for rendering (see above).
     * @param prefix if not passed, the endpoints will be `/login`, `/api/login` etc.  If you pass a prefix, it
     *               is prepended to the URLs (ie it is the prefix for the router),
     * @param loginRedirect upon successful login, a 302 Found redirect will take the user to this URL.  
     *                      Defaults to `/`.
     * @param logoutRedirect upon successful logout, a 302 Found redirect will take the user to this URL.  
     *                      Defaults to `/`.
     * @param views If you do not pass your own app, passing a directory name here will cause a Nunjucks renderer
     *              to be created with this directory/URL.  See the class
     *              documentation above for full description.
     * @param loginPage? Page to render the login page (with or without an error message).  See the class
     *                   documentation above for full description.
     * @param errorPage? Page to render error messages, including failed login.  See the class
     *                   documentation above for full description.
     * @param anonymousSessions if true, a session ID will be created even when the user is not logged in.
     *                          setting this to false means you will also not get CSRF tokens if the user is not logged in.
     * @param keepAnonymousSessionId if using anonymous sessions and this flag is set to true, the same session ID will
     *                               be kept after login.  By default this is false, and a new session ID is
     *                               created.  If, for example, you have a shopping basket that was created before
     *                               login, you may wish to set this to true.
     */
    constructor(
        sessionManager : CookieSessionManager, {
        app, 
        prefix, 
        loginRedirect, 
        logoutRedirect,
        views,
        loginPage,
        errorPage,
        anonymousSessions,
        keepAnonymousSessionId }: FastifyCookieAuthServerOptions = {}) {

        this.sessionManager = sessionManager;
        this.loginPage = loginPage;
        this.errorPage = errorPage;
        if (anonymousSessions != undefined) this.anonymousSessions = anonymousSessions;
        if (keepAnonymousSessionId != undefined) this.keepAnonymousSessionId = keepAnonymousSessionId;

        if (app) {
            this.app = app;
        } else {
            if (views) {
                nunjucks.configure(views, {
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
                    "views",
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

                    
        if (prefix) {
            this.prefix = prefix;
        } else {
            this.prefix = "/";
        }
        if (loginRedirect) {
            this.loginRedirect = loginRedirect;
        }
        if (logoutRedirect) {
            this.logoutRedirect = logoutRedirect;
        } 
        this.loginPage = loginPage;
                    
        if (views && loginPage) {
            this.app.get(this.prefix+'login', async (request : FastifyRequest<{Querystring : LoginParamsType}>, reply : FastifyReply) =>  {
                if (this.loginPage)  { // if is redundant but VC Code complains without it
                    let data : {next? : any, csrfToken: string|undefined} = {csrfToken: request.csrfToken};
                    if (request.query.next) {
                        data["next"] = request.query.next;
                    }
                    return reply.view(this.loginPage, data);
                }
            });
        }

        this.app.setErrorHandler(function (error, _request, _reply) {
            console.log(error);
          })

        this.app.addHook('onRequest', async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
            let csrfToken : string|undefined = undefined;
            let loggedInUser : User|undefined = undefined;
            if (this.anonymousSessions) {
                let {csrfCookie, user} = 
                    await this.createAnonymousSessionIdIfNoneExists(request, reply);
                csrfToken = csrfCookie.value;
                loggedInUser = user;
            }
            request.user = loggedInUser;
            request.csrfToken = csrfToken?csrfToken.split(".")[1]:undefined; // already validated so this will work;
        });
          
        this.app.post(this.prefix+'login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
    
            let next = request.body.next || this.loginRedirect;
            try {
                CrossauthLogger.logger.debug("Next page " + next);

                await this.login(request, reply, 
                (reply, _user) => {return reply.redirect(next)});
            } catch (e) {
                CrossauthLogger.logger.error(e);
                return this.handleError(e, reply, (reply, code, error) => {
                    if (this.loginPage) {
                        return reply.view(this.loginPage, {error: error, code: code, next: next, csrfToken: request.csrfToken});
                    } else if (this.errorPage) {
                        return reply.view(this.errorPage, {error: error, code: code, csrfToken: request.csrfToken});
                    } else {
                        return reply.send(`<html><head><title>Error</head><body>There has been an error: ${error}</body></html>`);
                    }
                    
                });
            }
        });

        this.app.post(this.prefix+'logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            try {
                await this.logout(request, reply, 
                (reply) => {return reply.redirect(this.logoutRedirect)});
            } catch (e) {
                CrossauthLogger.logger.error(e);
                this.handleError(e, reply, (reply, code, error) => {
                    if (this.errorPage) {
                        return reply.view(this.errorPage, {error: error, code: code});
                    } else {
                       return reply.send(`<html><head><title>Error</head><body>There has been an error: ${error}</body></html>`);
                    }
                    
                });
            }
        });

        this.app.post(this.prefix+'api/login', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
            try {
                await this.login(request, reply, 
                (reply, user) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : user})});
            } catch (e) {
                CrossauthLogger.logger.error(e);
                this.handleError(e, reply, (reply, code, error) => {
                    reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: code});                    
                });
                //this.handleException(e, reply, (reply, code, error) => {console.log("Error")});
            }
        });

        this.app.post(this.prefix+'api/logout', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) => {
            try {
                await this.logout(request, reply, 
                (reply) => {return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok"})});
                if (this.anonymousSessions) await this.createAnonymousSessionIdIfNoneExists(request, reply);
            } catch (e) {
                CrossauthLogger.logger.error(e);
                this.handleError(e, reply, (reply, code, error) => {
                    reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error: error, code: code});                    
                });
            }
        });

        this.app.get(this.prefix+'api/userforsessionkey', async (request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply) =>  {
            let cookies = request.cookies;
            try {
                if (!cookies || !(this.sessionManager.sessionCookieName in cookies)) {
                    throw new CrossauthError(ErrorCode.InvalidKey);
                }
                if (cookies[this.sessionManager.sessionCookieName] != undefined) {
                    let user = await this.sessionManager.userForSessionKey(cookies[this.sessionManager.sessionCookieName] || "");
                    return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "ok", user : user});
                }
            } catch (e) {
                let error = "Unknown error";
                if (e instanceof CrossauthError) {
                    let ce = e as CrossauthError;
                    switch (ce.code) {
                        case ErrorCode.UserNotExist:
                        case ErrorCode.PasswordNotMatch:
                            error = "Invalid username or password";
                            break;
                        default:
                            error = ce.message;
                    }
                }
                CrossauthLogger.logger.error(e);
                return reply.header('Content-Type', 'application/json; charset=utf-8').send({status: "error", error : error});

            }
        });
    }
    
    private async login(request : FastifyRequest<{ Body: LoginBodyType }>, reply : FastifyReply, 
        successFn : (res : FastifyReply, user? : User) => void) {
        await this.validateCsrfToken(request, reply)
        const username = request.body.username;
        const password = request.body.password;
        let sessionId = undefined;
        let cookies = request.cookies;
        if (this.anonymousSessions && this.keepAnonymousSessionId 
            && cookies && this.sessionManager.sessionCookieName in cookies) {
            sessionId = cookies[this.sessionManager.sessionCookieName];
        }

        let { sessionCookie, csrfCookie, user } = await this.sessionManager.login(username, password, sessionId);
        CrossauthLogger.logger.debug("Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        CrossauthLogger.logger.debug("Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options));
        reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        return successFn(reply, user);
    }

    private async logout(_request : FastifyRequest, reply : FastifyReply, 
        successFn : (reply : FastifyReply) => void) {
        let cookies = reply.cookies;
        if (cookies && this.sessionManager.sessionCookieName in cookies) {
            if (cookies[this.sessionManager.sessionCookieName] != undefined) {
                await this.sessionManager.logout(reply.cookies[this.sessionManager.sessionCookieName] || "");
            }
        }
        CrossauthLogger.logger.debug("Logout: clear cookie " + this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.sessionCookieName);
        reply.clearCookie(this.sessionManager.csrfCookieName);
        return successFn(reply);

    }

    private async createAnonymousSessionIdIfNoneExists(request : FastifyRequest, reply : FastifyReply) 
        : Promise<{sessionCookie: Cookie, csrfCookie: Cookie, user : User|undefined}> {
        let cookies = request.cookies;
        let sessionId : string|undefined = undefined;
        let csrfToken : string|undefined = undefined;
        if (cookies && this.sessionManager.sessionCookieName in cookies) {
            sessionId = cookies[this.sessionManager.sessionCookieName]||""
        };
        if (cookies && this.sessionManager.csrfCookieName in cookies) {
            csrfToken = cookies[this.sessionManager.csrfCookieName]||"";
        }
        let {sessionCookie, csrfCookie, user} = await this.sessionManager.createAnonymousSessionKeyIfNoneExists(sessionId, csrfToken);
        if (sessionId != sessionCookie.value) {
            CrossauthLogger.logger.debug("Creating session ID");
            reply.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
        }
        if (csrfToken != csrfCookie.value) {
            CrossauthLogger.logger.debug("Creating CSRF Token");
            reply.cookie(csrfCookie.name, csrfCookie.value, csrfCookie.options);
        }        
        return {sessionCookie, csrfCookie, user};
    };

    private handleError(e : any, reply : FastifyReply, errorFn : (reply : FastifyReply, code : ErrorCode, error : string) => void) {
        let error = "Unknown error";
        let code = ErrorCode.UnknownError;
        if (e instanceof CrossauthError) {
            let ce = e as CrossauthError;
            code = ce.code;
            switch (ce.code) {
                case ErrorCode.UserNotExist:
                case ErrorCode.PasswordNotMatch:
                    error = "Invalid username or password";
                    code = ErrorCode.UsernameOrPasswordInvalid;
                    break;
                default:
                    error = ce.message;
            }
        }
        CrossauthLogger.logger.error(e);

        return errorFn(reply, code, error);

    }

    private getSessionIdFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.sessionCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.sessionCookieName]
        }
        return undefined;
    }

    private getCsrfTokenFromCookie(request : FastifyRequest) : string|undefined{
        if (request.cookies && this.sessionManager.csrfCookieName in request.cookies) {       
            return request.cookies[this.sessionManager.csrfCookieName]
        }
        return undefined;
    }

    /**
     * Checks the CSRF token in the cookie and form field/header is valid.
     * 
     * Doesn't return a value.  Exits successfully if the token is present and valid.  Throws a
     * CrossauthError with ErrorCode.InvalidKey if it is not.
     * 
     * The token in the cookie must have a signature that matches its payload.  The payload must match
     * the value in the csrfToken form field or X-CROSSAUTH-CSRF header.
     * 
     * @param request the fastify request
     * @param _reply the fastify reply
     * @param sessionId if given, use this as the session ID.  If undefined, it is taken from the request cookie
     */
    async validateCsrfToken(request : FastifyRequest<{ Body: CsrfBodyType }>, 
                            _reply : FastifyReply,
                            sessionId? : string) {
        if (!sessionId) {
            sessionId = this.getSessionIdFromCookie(request);
            if (!sessionId) {
                CrossauthLogger.logger.debug("No session cookie found when validating CSRF token");
                throw new CrossauthError(ErrorCode.InvalidKey);
            }
        } 
        let formOrHeaderToken = this.getCsrfTokenFromFormOrHeader(request);
        if (!formOrHeaderToken) {
            CrossauthLogger.logger.debug("No CSRF form or header value found when validating CSRF token");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        let csrfToken = this.getCsrfTokenFromCookie(request);
        if (!csrfToken) {
            CrossauthLogger.logger.debug("No CSRF cookie found when validating CSRF token");
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        this.sessionManager.validateDoubleSubmitCsrfToken(csrfToken, sessionId, formOrHeaderToken);
    }

    private getCsrfTokenFromFormOrHeader(request : FastifyRequest<{ Body: CsrfBodyType }>) : string|undefined {
        let formOrHeaderToken  : string|undefined = undefined;
        if (request.body.csrfToken) {
            formOrHeaderToken = request.body.csrfToken;
        } else if (request.headers[CSRFHEADER]) {
            let headers = request.headers[CSRFHEADER]
            if (headers && Array.isArray(headers)) {
                formOrHeaderToken = headers[0];
            } else {
                formOrHeaderToken = headers;
            }            
        }
        return formOrHeaderToken;
    }

    /**
     * Starts the Fastify app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen({ port: port}, () =>
            CrossauthLogger.logger.info(`Starting fastify server on port ${port} with prefix '${this.prefix}'`),
        );

    }
}
