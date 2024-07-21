import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { toCookieSerializeOptions } from '@crossauth/backend';
import type { User } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type LoginReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    success: boolean
};

export type LogoutReturn = {
    success: boolean,
    error?: string,
    exception?: CrossauthError,
};

export class SvelteKitUserEndpoints {
    private sessionServer : SvelteKitSessionServer;
    private addToSession? : (request : RequestEvent, formData : {[key:string]:string}) => 
        {[key: string] : string|number|boolean|Date|undefined};

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        if (options.addToSession) this.addToSession = options.addToSession;
   }

    async login(event : RequestEvent) : Promise<LoginReturn> {

        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const username = data.get('username') ?? "";
            const persist = data.getAsBoolean('persist') ?? false;
            if (username == "") throw new CrossauthError(ErrorCode.InvalidUserame, "Username field may not be empty");
            
            // call implementor-provided hook to add additional fields to session key
            let extraFields = this.addToSession ? this.addToSession(event, formData) : {}

            // throw an exception if the CSRF token isn't valid
            //await this.validateCsrfToken(request);
            if (!event.locals.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

            // keep the old session ID.  If there was one, we will delete it after
            const oldSessionId = this.sessionServer.getSessionCookieValue(event);

            // log user in and get new session cookie, CSRF cookie and user
            // if 2FA is enabled, it will be an anonymous session
            let { sessionCookie, csrfCookie, user } = 
                await this.sessionServer.sessionManager.login(username, data.toObject(), extraFields, persist);
            // Set the new cookies in the reply
            CrossauthLogger.logger.debug(j({
                msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
                user: username
            }));
            event.cookies.set(sessionCookie.name,
                sessionCookie.value,
                toCookieSerializeOptions(sessionCookie.options));
            CrossauthLogger.logger.debug(j({
                msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
                user: username
            }));
            event.cookies.set(csrfCookie.name,
                csrfCookie.value,
                toCookieSerializeOptions(csrfCookie.options));
            event.locals.csrfToken = 
                await this.sessionServer.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);

            // delete the old session key if there was one
            if (oldSessionId) {
                try {
                    await this.sessionServer.sessionManager.deleteSession(oldSessionId);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({
                        msg: "Couldn't delete session ID from database",
                        hashOfSessionId: this.sessionServer.getHashOfSessionId(event)
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                }
            }

            event.locals.user = user;
            return { user, formData, success: true };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
            }
        }
    }

    async logout(event : RequestEvent) : Promise<LogoutReturn> {

        try {
            // logout
            if (event.locals.sessionId) {
                await this.sessionServer.sessionManager.logout(event.locals.sessionId);
            }

            // clear cookies
            CrossauthLogger.logger.debug(j({msg: "Logout: clear cookie " 
                + this.sessionServer.sessionManager.sessionCookieName}));
            event.cookies.delete(this.sessionServer.sessionManager.sessionCookieName, {path: "/"})
            event.cookies.delete(this.sessionServer.sessionManager.csrfCookieName, {path: "/"})
            if (event.locals.sessionId) {
                try {
                    await this.sessionServer.sessionManager.deleteSession(event.locals.sessionId);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({
                        msg: "Couldn't delete session ID from database",
                        hashOfSessionId: this.sessionServer.getHashOfSessionId(event)
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                }
            }

            // delete locals
            event.locals.sessionId = undefined;
            event.locals.csrfToken = undefined;
            event.locals.user = undefined;

            return { success: true }
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
            };
        }
    }

}