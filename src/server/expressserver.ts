import express, { Express, Request, Response } from "express";
import { CookieSessionManager } from './cookieauth';

export interface ExpressCookieAuthServerOptions {
    app? : Express,
    prefix? : string,
    loginRedirect? : string;
    logoutRedirect? : string;
}

export class ExpressCookieAuthServer {
    app : Express;
    prefix : string;
    loginRedirect = "/";
    logoutRedirect : string;
    sessionManager : CookieSessionManager;

    constructor(
        sessionManager : CookieSessionManager, {
        app, 
        prefix, 
        loginRedirect, 
        logoutRedirect }: ExpressCookieAuthServerOptions = {}) {
        this.sessionManager = sessionManager;
        if (app) {
            this.app = app;
        } else {
            this.app = express();
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
        } else {
            this.logoutRedirect = prefix + "login";
        }

        const router = express.Router();
        router.use(express.json());
        router.use(express.urlencoded({ extended: true }));

        router.post('/login', async (req : Request, res : Response) =>  {
            const username = req.body.username;
            const password = req.body.password;
            let cookie = await this.sessionManager.login(username, password);

            res.cookie(cookie.name, cookie.value, cookie.options);
            res.redirect(this.loginRedirect);
        });

        router.get('/logout', async (req : Request, res : Response) => {
            let cookies = req.cookies;
            if (this.sessionManager.cookieName in cookies) {
                await this.sessionManager.logout(this.sessionManager.cookieName);
            }
            res.clearCookie(this.sessionManager.cookieName);
            res.redirect(this.logoutRedirect);
        });

        this.app.use(this.prefix, router)
    }
    
    
    start(port : number = 3000) {
        this.app.listen(port, () =>
            console.log(`Starting express server on port ${port} with prefix '${this.prefix}'`),
        );

    }
        
}
