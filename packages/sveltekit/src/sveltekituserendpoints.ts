import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions } from './sveltekitsession';
import { toCookieSerializeOptions } from '@crossauth/backend';
import type { AuthenticationParameters } from '@crossauth/backend';
import type { User, UserInputFields } from '@crossauth/common';
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

export type SignupReturn = {
    user? : UserInputFields,
    factor2Data?:  {
        userData: { [key: string]: any },
        username: string,
        csrfToken: string | undefined
    },
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string|undefined},
    success: boolean,
    factor2Required?: boolean,
    emailVerificationRequired? : boolean
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

    /** Returns whether there is a user logged in with a cookie-based session
     */
        isSessionUser(event: RequestEvent) {
        return event.locals.user != undefined && event.locals.authType == "cookie";
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
                formData,
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
            event.cookies.delete(this.sessionServer.sessionManager.csrfCookieName, {path: "/"});

            // create new CSRF token
            const { csrfCookie, csrfFormOrHeaderValue } = await this.sessionServer.sessionManager.createCsrfToken();
            this.sessionServer.setCsrfCookie(csrfCookie, [], event );
            event.locals.csrfToken = csrfFormOrHeaderValue;

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

    async signup(event : RequestEvent) : Promise<SignupReturn> {

        let formData : {[key:string]:string|undefined}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            console.log(formData);
            const username = data.get('username') ?? "";
            let user : UserInputFields|undefined;

            // throw an error if the CSRF token is invalid
            if (this.isSessionUser(event) && !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            if (username == "") throw new CrossauthError(ErrorCode.InvalidUserame, "Username field may not be empty");
            
            // get factor2 from user input
            if (!formData.factor2) {
                formData.factor2 = this.sessionServer.allowedFactor2[0]; 
            }
            if (formData.factor2 && 
                !(this.sessionServer.allowedFactor2.includes(formData.factor2??"none"))) {
                throw new CrossauthError(ErrorCode.Forbidden, 
                    "Illegal second factor " + formData.factor2 + " requested");
            }
            if (formData.factor2 == "none" || formData.factor2 == "") {
                formData.factor2 = undefined;
            }
    
            // call implementor-provided function to create the user object (or our default)
            user = 
                this.sessionServer.createUserFn(event, formData, this.sessionServer.userStorage.userEditableFields);

            // ask the authenticator to validate the user-provided secret
            let passwordErrors = 
                this.sessionServer.authenticators[user.factor1].validateSecrets(formData);

            // get the repeat secrets (secret names prefixed with repeat_)
            const secretNames = this.sessionServer.authenticators[user.factor1].secretNames();
            let repeatSecrets : AuthenticationParameters|undefined = {};
            for (let field in formData) {
                if (field.startsWith("repeat_")) {
                    const name = field.replace(/^repeat_/, "");
                    // @ts-ignore as it complains about request.body[field]
                    if (secretNames.includes(name)) repeatSecrets[name] = 
                    formData[field];
                }
            }
            if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;


            // set the user's state to active, awaitingtwofactor or 
            // awaitingemailverification
            // depending on settings for next step
            user.state = "active";
            if (formData.factor2 && formData.factor2!="none") {
                user.state = "awaitingtwofactor";
            } else if (this.sessionServer.enableEmailVerification) {
                user.state = "awaitingemailverification";
            }

            // call the implementor-provided hook to validate the user fields
            let userErrors = this.sessionServer.validateUserFn(user);

            // report any errors
            let errors = [...userErrors, ...passwordErrors];
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.FormEntry, errors);
            }


            // See if the user was already created, with the correct password, and 
            // is awaiting 2FA
            // completion.  Send the same response as before, in case the user 
            // closed the browser
            let twoFactorInitiated = false;
            try {
                const {user: existingUser, secrets: existingSecrets} = 
                await this.sessionServer.userStorage.getUserByUsername(username);
                await this.sessionServer.sessionManager.authenticators[user.factor1]
                    .authenticateUser(existingUser, existingSecrets, formData);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                if (ce.code == ErrorCode.TwoFactorIncomplete) {
                    twoFactorInitiated = true;
                } // all other errors are legitimate ones - we ignore them
            }

            // login (this may be just first stage of 2FA)
            if ((!formData.factor2) && !twoFactorInitiated) {
                // not enabling 2FA
                await this.sessionServer.sessionManager.createUser(user,
                    formData,
                    repeatSecrets);
                    if (!this.sessionServer.enableEmailVerification) {
                        return {...await this.login(event), formData: formData};
                }
                // email verification sent - tell user
                return {emailVerificationRequired: true, user: user, success: true, formData: formData};
            } else {
                // also enabling 2FA
                let userData : {[key:string] : any};
                if (twoFactorInitiated) {
                    // account already created but 2FA setup not complete
                    if (!event.locals.sessionId) throw new CrossauthError(ErrorCode.Unauthorized);
                    const resp = 
                        await this.sessionServer.sessionManager.repeatTwoFactorSignup(event.locals.sessionId);
                    userData = resp.userData;
                } else {
                    // account not created - create one with state awaiting 2FA setup
                    const sessionValue = 
                        await this.sessionServer.createAnonymousSession(event);
                    const sessionId = this.sessionServer.sessionManager.getSessionId(sessionValue);
                    const resp = 
                        await this.sessionServer.sessionManager.initiateTwoFactorSignup(user,
                            formData,
                            sessionId,
                            repeatSecrets);
                    userData = resp.userData;
                }

                // pass caller back 2FA parameters
                try {
                    let data: {
                        userData: { [key: string]: any },
                        username: string,
                        csrfToken: string | undefined
                    } = 
                    {
                        userData: userData,
                        username: username,
                        csrfToken: event.locals.csrfToken,
                    };
                    return { factor2Data: data, success: true, factor2Required: true, formData};
                } catch (e) {
                    // if there is an error, make sure we delete the user before returning
                    CrossauthLogger.logger.error(j({err: e}));
                    try {
                        this.sessionServer.sessionManager.deleteUserByUsername(username);
                    } catch (e) {
                        CrossauthLogger.logger.error(j({err: e}));
                    }

                }


            }

            return { user, formData, success: true };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        }
    }
}