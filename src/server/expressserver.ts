import express, { Express, Request, Response } from "express";
import nunjucks from "nunjucks";
import { CookieSessionManager } from './cookieauth';
import { CrossauthError, ErrorCode, CrossauthLogger } from "..";
import cookieParser from 'cookie-parser';
import { User } from '../interfaces';

/**
 * Options for {@link ExpressCookieAuthServer }.
 * 
 * See {@link ExpressCookieAuthServer } constructor for description of parameters
 */
export interface ExpressCookieAuthServerOptions {
    app? : Express,
    prefix? : string,
    loginRedirect? : string;
    logoutRedirect? : string;
    views? : string;
    loginPage? : string;
    errorPage? : string;
}

/**
 * This class provides a complete (but without HTML files) auth backend server with endpoints served using Express.
 * 
 * If you do not pass an Express app to this class, it will create one.  If you set the views parameter, it
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
 *    **Using your own Express app**
 * 
 * If you are serving other endpoints, or you want to use something other than Nunjucks, you can create and
 * pass in your own Express app.
 */
export class ExpressCookieAuthServer {
    readonly app : Express;
    private prefix : string;
    private loginRedirect = "/";
    private logoutRedirect : string = "/";
    private loginPage? : string;
    private errorPage? : string;
    private sessionManager : CookieSessionManager;

    /**
     * Creates the Express endpoints, optionally also the Express app.
     * @param sessionManager an instance of {@link CookieSessionManager }.  The endpoints are just wrappers
     *                       around this, adding the HTTP interaction.
     * @param app you can pass your own Express instance.  A separate router will be added for the endpoints.  
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
     */
    constructor(
        sessionManager : CookieSessionManager, {
        app, 
        prefix, 
        loginRedirect, 
        logoutRedirect,
        views,
        loginPage,
        errorPage }: ExpressCookieAuthServerOptions = {}) {

        this.sessionManager = sessionManager;
        this.loginPage = loginPage;
        this.errorPage = errorPage;
        if (app) {
            this.app = app;
        } else {
            this.app = express();
            if (views) {
                nunjucks.configure(views, {
                    autoescape: true,
                    express: app
                });
            }

        }
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

        const router = express.Router();
        router.use(express.json());
        router.use(express.urlencoded({ extended: true }));
        router.use(cookieParser());

        if (views && loginPage) {
            router.get('/login', async (_req : Request, res : Response) =>  {
                if (this.loginPage)  { // if is reduntant but VC Code complains without it
                    res.render(this.loginPage);
                }
            });
        }

        router.post('/login', async (req : Request, res : Response) =>  {
            try {
                await this.login(req, res, (res, _user) => {res.redirect(this.loginRedirect)});
            } catch (e) {
                console.log(e);
                this.handleError(e, res, (res, code, error) => {
                    if (this.loginPage) {
                        res.render(this.loginPage, {error: error, code: code});
                    } else if (this.errorPage) {
                        res.render(this.errorPage, {error: error, code: code});
                    } else {
                        res.send(`<html><head><title>Error</head><body>There has been an error: ${error}</body></html>`);
                    }                
                });

            }
        });

        router.get('/logout', async (req : Request, res : Response) => {
            try {
                await this.logout(req, res, (res) => {res.redirect(this.logoutRedirect);});
            } catch (e) {
                console.log(e);
                this.handleError(e, res, (res, code, error) => {
                    if (this.errorPage) {
                        res.render(this.errorPage, {error: error, code: code});
                    } else {
                        res.send(`<html><head><title>Error</head><body>There has been an error: ${error}</body></html>`);
                    }
                });

            }
        });

        router.post('/api/login', async (req : Request, res : Response) =>  {
            try {
                await this.login(req, res, (res, user) => {res.json({status: "ok", user : user});});
            } catch (e) {
                console.log(e);
                this.handleError(e, res, (reply, code, error) => {
                    reply.json({status: "error", error: error, code: code});                    
                });
                //this.handleException(e, reply, (reply, code, error) => {console.log("Error")});

            }
        });

        router.post('/api/logout', async (req : Request, res : Response) => {
            try {
                await this.logout(req, res, (res) => {res.json({status: "ok"});});
            } catch (e) {
                console.log(e);
                this.handleError(e, res, (res, code, error) => {
                    res.json({status: "error", error: error, code: code});                    
                });

            }
        });

        router.get('/api/userforsessionkey', async (req : Request, res : Response) =>  {
            let cookies = req.cookies;
            try {
                if (!cookies || !(this.sessionManager.sessionCookieName in cookies)) {
                    CrossauthLogger.logger.debug("User requested but no session ID cookie passed");
                    throw new CrossauthError(ErrorCode.InvalidKey);
                }
                let user = await this.sessionManager.userForSessionKey(cookies[this.sessionManager.sessionCookieName]);
                res.json({status: "ok", user : user});
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
                res.json({status: "error", error : error});

            }
        });

        this.app.use(this.prefix, router);
    }
    
    private async login(req : Request, res : Response, successFn : (res : Response, user? : User) => void) {
        const username = req.body.username;
        const password = req.body.password;

        try {
            let { sessionCookie, user } = await this.sessionManager.login(username, password);

            res.cookie(sessionCookie.name, sessionCookie.value, sessionCookie.options);
            //res.json({status: "ok", user : user});
            return successFn(res, user);
        } catch (e) {
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

            res.json({status: "error", error : error, code: code});
        }
    };

    private async logout(req : Request, res : Response, successFn : (res : Response) => void) {
        let cookies = req.cookies;
        if (cookies && this.sessionManager.sessionCookieName in cookies) {
            await this.sessionManager.logout(this.sessionManager.sessionCookieName);
        }
        res.clearCookie(this.sessionManager.sessionCookieName);
        //res.json({status: "ok"});
        successFn(res);

    }

    private handleError(e : any, res : Response, errorFn : (res : Response, code : ErrorCode, error : string) => void) {
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

        errorFn(res, code, error);

    }

    /**
     * Starts the Express app on the given port.  
     * @param port the port to listen on
     */
    start(port : number = 3000) {
        this.app.listen(port, () =>
            CrossauthLogger.logger.info(`Starting express server on port ${port} with prefix '${this.prefix}'`),
        );

    }
        
}
