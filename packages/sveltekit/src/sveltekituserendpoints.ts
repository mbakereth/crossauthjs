import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions, SveltekitEndpoint } from './sveltekitsession';
import { 
    toCookieSerializeOptions,     
    setParameter,
    ParamType,
 } from '@crossauth/backend';
import type { AuthenticationParameters } from '@crossauth/backend';
import type { User, UserInputFields } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode, UserState } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type LoginReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    factor2Required?: boolean,
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
        csrfToken?: string | undefined,
        factor2: string,
    },
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string|undefined},
    success: boolean,
    factor2Required?: boolean,
    emailVerificationRequired? : boolean
};

export type ConfigureFactor2Return = {
    user? : UserInputFields,
    factor2Data?:  {
        userData: { [key: string]: any },
        username: string,
        csrfToken?: string | undefined,
        factor2: string,
    },
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string|undefined},
    success: boolean,
    emailVerificationRequired? : boolean
};

export type VerifyEmailReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    success: boolean
};

export type RequestPasswordResetReturn = {
    user? : User,
    formData?: {[key:string]:string|undefined},
    error?: string,
    exception?: CrossauthError,
    success: boolean
};

export type ResetPasswordReturn = {
    user? : User,
    formData?: {[key:string]:string|undefined},
    error?: string,
    exception?: CrossauthError,
    success: boolean
};

export type RequestFactor2Return = {
    success: boolean,
    action?: string,
    factor2?: string,
    error?: string,
    exception?: CrossauthError,
    csrfToken? : string,
};

export type ChangePasswordReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    success: boolean
};

export type ChangeFactor2Return = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    success: boolean,
    factor2Data?:  {
        userData: { [key: string]: any },
        username: string,
        csrfToken?: string | undefined,
        factor2: string,
    },
};

export type DeleteUserReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    success: boolean
};

export type UpdateUserReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    emailVerificationNeeded: boolean,
    success: boolean
};

/**
 * Provides endpoints for users to login, logout and maintain their 
 * own account.
 * 
 * This class is not intended to be used outside of Crossauth.  For 
 * documentation about functiuons it provides, see
 * {@link SvelteKitSessionServer}.
 */
export class SvelteKitUserEndpoints {
    private sessionServer : SvelteKitSessionServer;
    private changePasswordUrl = "/changepassword";
    private changeFactor2Url = "/changefactor2";
    private requestPasswordResetUrl = "/resetpassword";
    private loginRedirectUrl = "/";
    private loginUrl = "/login";
    private addToSession? : (request : RequestEvent, formData : {[key:string]:string}) => 
        {[key: string] : string|number|boolean|Date|undefined};

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        setParameter("changePasswordUrl", ParamType.String, this, options, "CHANGE_PASSWORD_URL");
        setParameter("requestPasswordResetUrl", ParamType.String, this, options, "REQUEST_PASSWORD_RESET_URL");
        setParameter("changeFactor2Url", ParamType.String, this, options, "CHANGE_FACTOR2_URL");
        setParameter("loginRedirectUrl", ParamType.JsonArray, this, options, "LOGIN_REDIRECT_URL");
        setParameter("loginUrl", ParamType.JsonArray, this, options, "LOGIN_URL");
        if (options.addToSession) this.addToSession = options.addToSession;
    }

    /** Returns whether there is a user logged in with a cookie-based session
     */
    isSessionUser(event: RequestEvent) {
        return event.locals.user != undefined && event.locals.authType == "cookie";
    }

    /**
     * A user can edit his or her account if they are logged in with
     * session management, or are logged in with some other means and
     * e`ditUserScope` has been set and is included in the user's scopes.
     * @param request the Fastify request
     * @returns true or false
     */
    canEditUser(event : RequestEvent) {
        return this.isSessionUser(event) || 
            (this.sessionServer.editUserScope && event.locals.scope && 
                event.locals.scope.includes(this.sessionServer.editUserScope));
    }
    
    ////////////////////////////////////////////////////
    // Functions for calling manually from own Actions or PageLoad

    /**
     * Log a user in if possible.  
     * 
     * Form data is returned unless there was
     * an error extrafting it.  User is returned if log in was successful.
     * Error messge and exception are returned if not successful.
     * 
     * @param event the Sveltekit event.  The fields needed are:
     * 
     *   - `username`.
     *   - *secrets* (eg `password`).
     *   - `repeat_`*secrets* (eg `repeat_password`).
     * 
     *   The secrets are authenticator-dependent.
     * 
     * @returns object with:
     * 
     *   - `success` true if login was successful, false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `factor2Required` if true, second factor authentication is needed
     *     to complete login
     */
    async login(event : RequestEvent) : Promise<LoginReturn> {

        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const username = data.get('username') ?? "";
            const persist = data.getAsBoolean('persist') ?? false;
            const next = formData.next ?? this.loginRedirectUrl;
            if (username == "") throw new CrossauthError(ErrorCode.InvalidUsername, "Username field may not be empty");
            
            // call implementor-provided hook to add additional fields to session key
            let extraFields = this.addToSession ? this.addToSession(event, formData) : {}

            // throw an exception if the CSRF token isn't valid
            //await this.validateCsrfToken(request);
            if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

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
            if (this.sessionServer.enableCsrfProtection) {
                event.cookies.set(csrfCookie.name,
                    csrfCookie.value,
                    toCookieSerializeOptions(csrfCookie.options));
                event.locals.csrfToken = 
                    await this.sessionServer.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);    
            }

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

            if (user.state == UserState.passwordChangeNeeded) {
                this.sessionServer.redirect(302, this.changePasswordUrl + "?required=true&next="+encodeURIComponent("login?next="+next));
            } else if (user.state == UserState.passwordResetNeeded) {
                this.sessionServer.redirect(302, this.requestPasswordResetUrl);
            } else if (this.sessionServer.allowedFactor2.length > 0 && 
                user.state == UserState.factor2ResetNeeded || 
                !this.sessionServer.allowedFactor2Names.includes(user.factor2?user.factor2:"none")) {
                    this.sessionServer.redirect(302, this.changeFactor2Url + "?required=true&next="+encodeURIComponent("login?next="+next));
            } else {
                if (!user.factor2 || user.factor2 == "")
                    event.locals.user = user;
            }
            return { 
                user, 
                formData, 
                factor2Required: user.factor2 && user.factor2 != "",
                success: true, 
            };    
        } catch (e) {
            // hack - let Sveltekit redirect through
            if (typeof e == "object" && e != null && "status" in e && "location" in e) throw e
            let ce = CrossauthError.asCrossauthError(e, "Couldn't log in");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        }
    }

    /**
     * This is called after the user has been validated to log the user in
     */
    private async loginWithUser(user: User, 
        bypass2FA : boolean, 
        event : RequestEvent) {

        // get old session ID so we can delete it after
        const oldSessionId = event.locals.sessionId;

        // call implementor-provided hook to add custom fields to session key
        const data = new JsonOrFormData();
        await data.loadData(event);
        let extraFields = this.addToSession ? this.addToSession(event, data.toObject()) : {}

        // log user in - this doesn't do any authentication
        let { sessionCookie, csrfCookie, csrfFormOrHeaderValue } = 
            await this.sessionServer.sessionManager.login("", {}, extraFields, undefined, user, bypass2FA);

        // set the cookies
        CrossauthLogger.logger.debug(j({
            msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user.username
        }));
        event.cookies.set(sessionCookie.name,
            sessionCookie.value,
            toCookieSerializeOptions(sessionCookie.options));
        CrossauthLogger.logger.debug(j({
            msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
            user: user.username
        }));
        if (this.sessionServer.enableCsrfProtection)
            event.cookies.set(csrfCookie.name, 
                csrfCookie.value, 
                toCookieSerializeOptions(csrfCookie.options));

        // set locals
        event.locals.user = user;
        event.locals.csrfToken = csrfFormOrHeaderValue;
        event.locals.sessionId = this.sessionServer.sessionManager.getSessionId(sessionCookie.value);

        // delete the old session
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

        return {
            user: user,
            success: true,
        };
    }
    

    /**
     * Log a user out.  
     * 
     * Deletes the session if the user was logged in and clears session
     * and CSRF cookies (if CSRF protection is enabled)
     * 
     * @param event the Sveltekit event
     * 
     * @returns object with:
     * 
     *   - `success` true if logout was successful, false otherwise.
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     */
    async logout(event : RequestEvent) : Promise<LogoutReturn> {

        try {
            // logout
            if (event.locals.sessionId) {
                await this.sessionServer.sessionManager.logout(event.locals.sessionId);
            }

            // clear cookies
            CrossauthLogger.logger.debug(j({msg: "Logout: clear cookie " 
                + this.sessionServer.sessionManager.sessionCookieName}));
            event.cookies.delete(this.sessionServer.sessionManager.sessionCookieName, {path: "/"});
            if (this.sessionServer.enableCsrfProtection)
                event.cookies.delete(this.sessionServer.sessionManager.csrfCookieName, {path: "/"});
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
            event.locals.user = undefined;
            if (this.sessionServer.enableCsrfProtection) {
                event.locals.csrfToken = undefined;
                event.cookies.delete(this.sessionServer.sessionManager.csrfCookieName, {path: "/"});

                // create new CSRF token
                const { csrfCookie, csrfFormOrHeaderValue } = await this.sessionServer.sessionManager.createCsrfToken();
                this.sessionServer.setCsrfCookie(csrfCookie, event );
                event.locals.csrfToken = csrfFormOrHeaderValue;
            }

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

    /**
     * Creates an account. 
     * 
     * Form data is returned unless there was an error extrafting it. 
     * 
     * Initiates user login if creation was successful. 
     * 
     * If login was successful, no factor2 is needed
     * and no email verification is needed, the user is returned.
     * 
     * If email verification is needed, `emailVerificationRequired` is 
     * returned as `true`.
     * 
     * If factor2 configuration is required, `factor2Required` is returned
     * as `true`.
     * 
     * @param event the Sveltekit event.  The form fields used are
     *   - `username` the desired username
     *   - `factor2` which must be in the `allowedFactor2` option passed
     *     to the constructor.
     *   - *secrets* (eg `password`) which are factor1 authenticator specific
     *   - `repeat_`*secrets* (eg `repeat_password`)
     *   - `user_*` anything prefixed with `user` that is also in
     *   - the `userEditableFields` option passed when constructing the
     *     user storage object will be added to the {@link @crossuath/common!User}
     *     object (with `user_` removed).
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `factor2Required` if true, second factor authentication is needed
     *     to complete login
     *   - `factor2Data` contains data that needs to be passed to the user's
     *      chosen factor2 authenticator
     *   - `emailVerificationRequired` if true, the user needs to click on
     *     the link emailed to them to complete signup.
     */
    async signup(event : RequestEvent) : Promise<SignupReturn> {

        let formData : {[key:string]:string|undefined}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const username = data.get('username') ?? "";
            let user : UserInputFields|undefined;

            // throw an error if the CSRF token is invalid
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            if (username == "") throw new CrossauthError(ErrorCode.InvalidUsername, "Username field may not be empty");
            
            // get factor2 from user input
            if (!formData.factor2) {
                formData.factor2 = this.sessionServer.allowedFactor2Names[0]; 
            }
            if (formData.factor2 && 
                !(this.sessionServer.allowedFactor2Names.includes(formData.factor2??"none"))) {
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
                        csrfToken?: string | undefined,
                        factor2: string,
                    } = 
                    {
                        userData: userData,
                        username: username,
                        factor2: formData.factor2 ?? "none",
                    };
                    if (this.sessionServer.enableCsrfProtection)
                        data.csrfToken = event.locals.csrfToken;

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

    /**
     * Takes email verification token from the params on the URL and attempts 
     * email verification.
     * 
     * @param event the Sveltekit event.  This should contain the URL
     *        parameter called `token` 
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `factor2Required` if true, second factor authentication is needed
     *     to complete login
     *   - `factor2Data` contains data that needs to be passed to the user's
     *      chosen factor2 authenticator
     *   - `emailVerificationRequired` if true, the user needs to click on
     *     the link emailed to them to complete signup.
     */
    async verifyEmail(event : RequestEvent) : Promise<VerifyEmailReturn> {
        try {

            const token = event.params.token;
            if (!token) throw new CrossauthError(ErrorCode.InvalidToken, "Invalid email verification token");

            // validate the token and log the user in
            const user = 
                await this.sessionServer.sessionManager.applyEmailVerificationToken(token);
            await this.loginWithUser(user, true, event);
            if (event.locals.user) {
                const resp = await this.sessionServer.userStorage.getUserById(event.locals.user?.id);
                event.locals.user = resp.user;
            }

            return {
                success: true,
                user: user,
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
            };
        }
    }

    /**
     * Completes factor2 configuration.  
     * 
     * 2FA configuration is initiated with {@link signup()}, or 
     * {@link changeFactor2()}.  If these return successfully, call this 
     * function.
     * 
     * @param event the Sveltekit event.  This should contain fields
     *        required by the user's chosen authenticator.
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `user` the user successful
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `emailVerificationRequired` if true, the user needs to click on
     *     the link emailed to them to complete configuration.
     */
    async configureFactor2(event : RequestEvent) : Promise<ConfigureFactor2Return> {

        let formData : {[key:string]:string|undefined}|undefined = undefined;
        let factor2Data : {userData: {[key:string]:any}, username: string, csrfToken? : string, factor2: string}|undefined = undefined;
        let factor2 = "";
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // get factor2 type from session data 
            const sessionData = await this.sessionServer.getSessionData(event, "2fa");
            if (sessionData?.factor2) factor2 = sessionData?.factor2;
            else throw new CrossauthError(ErrorCode.BadRequest, "Two factor authentication was not started");

            // throw an error if the CSRF token is invalid
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            // get the session - it may be a real user or anonymous
            if (!event.locals.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, 
                "No session active while enabling 2FA.  Please enable cookies");
            // finish 2FA setup - validate secrets and update user
            let user = await this.sessionServer.sessionManager.completeTwoFactorSetup(formData, 
                event.locals.sessionId);
            /*if (!this.isSessionUser(event) && !this.sessionServer.enableEmailVerification) {
                // we skip the login if the user is already logged in and we are not doing email verification
                await this.loginWithUser(user, true, event);
            }*/
            if (!this.sessionServer.enableEmailVerification) {
                // if email verification is enabled, the user will have
                // to click on their link before logging in.  
                // completeTwoFactorSetup() already sent the email
                await this.loginWithUser(user, true, event);
            }


            return {
                success: true,
                user: user,
                emailVerificationRequired: this.sessionServer.enableEmailVerification,
            };

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);

            // get user data for 2fa again so that we can show it to
            // the user again
            let userData : {[key:string]:any}|undefined = undefined;
            try {
                const resp = await this.sessionServer.sessionManager.repeatTwoFactorSignup(event.locals.sessionId ?? "");
                userData = resp.userData;
            } catch (e2) {}
            if (userData)
                factor2Data = {
                    userData: userData,
                    csrfToken: event.locals.csrfToken,
                    username: userData.username ?? "",
                    factor2: factor2,
                };

            return {
                success: false,
                error: ce.message,
                exception: ce,
                formData: formData,
                factor2Data: factor2Data,
                emailVerificationRequired: this.sessionServer.enableEmailVerification,
            };
        }
    }

    /**
     * Call this when `login()` returns `factor2Required = true`
     *
     * @param event the Sveltekit event.  The fields needed are those
     *        required by the factor2 authenticator.
     * 
     * @returns object with:
     * 
     *   - `success` true if login was successful, false otherwise.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     */
    async loginFactor2(event : RequestEvent) : Promise<LoginReturn> {
        if (event.locals.user) {
            return {
                user: event.locals.user,
                success: true,            
            }
        }

        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const persist = data.getAsBoolean('persist') ?? false;

            // save the old session ID so we can delete it after (the anonymous session)
            // If there isn't one it is an error - only allowed to this URL with a 
            // valid session
            const oldSessionId = event.locals.sessionId;
            if (!oldSessionId) throw new CrossauthError(ErrorCode.Unauthorized);

            // validate CSRF token - throw an exception if it is not valid
            //await this.validateCsrfToken(request);
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && 
                !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            let extraFields = this.addToSession ? this.addToSession(event, formData) : {}
            const {sessionCookie, csrfCookie, user} = 
            await this.sessionServer.sessionManager.completeTwoFactorLogin(formData, 
                oldSessionId, 
                extraFields, 
                persist);
            CrossauthLogger.logger.debug(j({
                msg: "Login: set session cookie " + sessionCookie.name + " opts " + JSON.stringify(sessionCookie.options),
                user: user?.username
            }));
            event.cookies.set(
                sessionCookie.name,
                sessionCookie.value,
                toCookieSerializeOptions(sessionCookie.options));
            CrossauthLogger.logger.debug(j({
                msg: "Login: set csrf cookie " + csrfCookie.name + " opts " + JSON.stringify(sessionCookie.options),
                user: user?.username
            }));
            event.cookies.set(
                csrfCookie.name, 
                csrfCookie.value, 
                toCookieSerializeOptions(csrfCookie.options));
            if (this.sessionServer.enableCsrfProtection)
                event.locals.csrfToken = 
                    await this.sessionServer.sessionManager.createCsrfFormOrHeaderValue(csrfCookie.value);
            event.locals.user = user;

            return {
                user: user,
                success: true,            
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
                formData: formData,
            }
        }
    }

    async requestPasswordReset(event : RequestEvent) : Promise<RequestPasswordResetReturn> {
        let formData : {[key:string]:string|undefined}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const email = data.get('email') ?? "";
            if (email == "") throw new CrossauthError(ErrorCode.InvalidUsername, "Email field may not be empty");
            // throw an error if the CSRF token is invalid
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            // this has to be enabled in configuration
            if (!this.sessionServer.enablePasswordReset) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "Password reset not enabled");
            }

            // Send password reset email
            await this.sessionServer.sessionManager.requestPasswordReset(email);


            return { formData, success: true };

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

    /**
     * Call this from the GET url the user clicks on to reset their password.
     * 
     * If it is enabled, fetches the user for the token to confirm the token
     * is valid.

     * @param event the Sveltekit event.  This should a `token` URL parameter.

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `user` the user successful
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `formData` the form fields extracted from the request
     */
    async validatePasswordResetToken(event : RequestEvent) : Promise<ResetPasswordReturn> {
        CrossauthLogger.logger.debug(j({msg:"validatePasswordResetToken " + event.request.method}))
        try {

            const token = event.params.token;
            if (!token) throw new CrossauthError(ErrorCode.InvalidToken, "Invalid email verification token");

            // validate the token and log the user in
            const user = 
                await this.sessionServer.sessionManager.userForPasswordResetToken(token);

            return {
                success: true,
                user: user,
                formData : {token}
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
            };
        }

    }

    /**
     * Call this from the POST url the user uses to fill in a new password
     * after validating the token in the GET url with
     * {@link validatePasswordResetToken}.
     * 
     * @param event the Sveltekit event.  This should contain
     *   - `new_`*secrets` (eg `new_password`) the new secret.
     *   - `repeat_`*secrets` (eg `repeat_password`) repeat of the new secret.

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `user` the user if successful
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `formData` the form fields extracted from the request
     */
    async resetPassword(event : RequestEvent) : Promise<ResetPasswordReturn> {
        CrossauthLogger.logger.debug(j({msg:"resetPassword"}));
        let formData : {[key:string]:string|undefined}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // throw an error if the CSRF token is invalid
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) 
                throw new CrossauthError(ErrorCode.InvalidCsrf);

            // this has to be enabled in configuration
            if (!this.sessionServer.enablePasswordReset) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "Password reset not enabled");
            }

            // get user for token
            const token = event.params.token ?? "";
            if (token == "") throw new CrossauthError(ErrorCode.InvalidUsername, "No token provided");
            const user = await this.sessionServer.sessionManager.userForPasswordResetToken(token);

            // get secrets from the request body 
            // there should be new_{secret} and repeat_{secret}
            const authenticator = this.sessionServer.authenticators[user.factor1];
            const secretNames = authenticator.secretNames();
            let newSecrets : AuthenticationParameters = {};
            let repeatSecrets : AuthenticationParameters|undefined = {};
            for (let field in formData) {
                if (field.startsWith("new_")) {
                    const name = field.replace(/^new_/, "");
                    // @ts-ignore as it complains about formData[field]
                    if (secretNames.includes(name)) newSecrets[name] = formData[field];
                } else if (field.startsWith("repeat_")) {
                    const name = field.replace(/^repeat_/, "");
                    // @ts-ignore as it complains about formData[field]
                    if (secretNames.includes(name)) repeatSecrets[name] = formData[field];
                }
            }
            if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

            // validate the new secrets (with the implementor-provided function)
            let errors = authenticator.validateSecrets(newSecrets);
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.PasswordFormat);
            }

            // check new and repeat secrets are valid and update the user
            const user1 = await this.sessionServer.sessionManager.resetSecret(token, 1, newSecrets, repeatSecrets);
            // log the user in
            return this.loginWithUser(user1, true, event);

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

    /**
     * Call this from your factor2 endpoint to fetch the data needed to
     * display the factor2 form.
     * 
     * This can only be called after 2FA has been initiated by visiting
     * a page with factor2 protection, as defined by the 
     * `factor2ProtectedPageEndpoints` and `factor2ProtectedApiEndpoints` 
     * defined when constructing this class.
     * 
     * @param event the Sveltekit event.  

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `action` the URL to load on success.  This was the one originally
     *     requested by the user before being redirected to 2FA authentication.
     *   - `factor2` the user's factor2
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     */
    async requestFactor2(event : RequestEvent) : Promise<RequestFactor2Return> {
        try {

            if (!event.locals.sessionId) throw new CrossauthError(ErrorCode.Unauthorized, 
                "No session cookie present");
            const sessionCookieValue = this.sessionServer.getSessionCookieValue(event);
            const sessionId = this.sessionServer.sessionManager.getSessionId(sessionCookieValue??"")
            const sessionData = 
            await this.sessionServer.sessionManager.dataForSessionId(sessionId);
            if (!sessionData?.pre2fa) throw new CrossauthError(ErrorCode.Unauthorized, 
                "2FA not initiated");
            return {
                success: true,
                csrfToken: event.locals.csrfToken, 
                action: sessionData.pre2fa.url, 
                factor2: sessionData.pre2fa.factor2
            };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "2FA failed");
            return {
                error: ce.message,
                exception: ce,
                success: false,
            }
        }
    }

    /**
     * Call this with POST data to change the logged-in user's password
     * 
     * @param event the Sveltekit event.  This should contain
     *   - `old_`*secrets` (eg `old_password`) the existing secret.
     *   - `new_`*secrets` (eg `new_password`) the new secret.
     *   - `repeat_`*secrets` (eg `repeat_password`) repeat of the new secret.

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `user` the user if successful
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `formData` the form fields extracted from the request
     */
    async changePassword(event : RequestEvent) : Promise<ChangePasswordReturn> {
        CrossauthLogger.logger.debug(j({msg:"changePassword"}));
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // can only call this if logged in and CSRF token is valid,
            // or else if login has been initiated but a password change is
            // required
            let user : User;
            let required = false;
            if (!this.isSessionUser(event) || !event.locals.user) {
                // user is not logged on - check if there is an anonymous 
                // session with passwordchange set (meaning the user state
                // was set to changepasswordneeded when logging on)
                const data = await this.sessionServer.getSessionData(event, "passwordchange")
                if (data?.username) {
                    const resp = await this.sessionServer.userStorage.getUserByUsername(
                        data?.username, {
                            skipActiveCheck: true,
                            skipEmailVerifiedCheck: true,
                        });
                    user = resp.user;
                    required = true;
                    if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                        throw new CrossauthError(ErrorCode.InvalidCsrf);
                    }
                } else {
                    throw new CrossauthError(ErrorCode.Unauthorized);
                }
            } else if (!this.canEditUser(event)) {
                throw new CrossauthError(ErrorCode.InsufficientPriviledges);
            } else {
                //this.validateCsrfToken(request)
                if (this.isSessionUser(event) && 
                    this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                    throw new CrossauthError(ErrorCode.InvalidCsrf);
                }
                user = event.locals.user;
            }
    
            // get the authenticator for factor1 (passwords on factor2 are not supported)
            const authenticator = this.sessionServer.authenticators[user.factor1];

            // the form should contain old_{secret}, new_{secret} and repeat_{secret}
            // extract them, making sure the secret is a valid one
            const secretNames = authenticator.secretNames();
            let oldSecrets : AuthenticationParameters = {};
            let newSecrets : AuthenticationParameters = {};
            let repeatSecrets : AuthenticationParameters|undefined = {};
            for (let field in formData) {
                if (field.startsWith("new_")) {
                    const name = field.replace(/^new_/, "");
                    if (secretNames.includes(name)) newSecrets[name] = formData[field];
                } else if (field.startsWith("old_")) {
                    const name = field.replace(/^old_/, "");
                    if (secretNames.includes(name)) oldSecrets[name] = formData[field];
                } else if (field.startsWith("repeat_")) {
                    const name = field.replace(/^repeat_/, "");
                    if (secretNames.includes(name)) repeatSecrets[name] = formData[field];
                }
            }
            if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;

            // validate the new secret - this is through an implementor-supplied function
            let errors = authenticator.validateSecrets(newSecrets);
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.PasswordFormat);
            }

            // validate the old secrets, check the new and repeat ones match and 
            // update if valid
            const oldState = user.state;
            try {
                if (required) {
                    user.state = "active";
                    await this.sessionServer.userStorage.updateUser({id: user.id, state:user.state});
                }
                await this.sessionServer.sessionManager.changeSecrets(user.username,
                    1,
                    newSecrets,
                    repeatSecrets,
                    oldSecrets
                );
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: e}));
                if (required) {
                    try {
                        await this.sessionServer.userStorage.updateUser({id: user.id, state: oldState});
                    } catch (e2) {
                        CrossauthLogger.logger.debug(j({err: e2}));
                    }
                }
                throw ce; 
            }

            if (required) {
                // this was a forced change - user is not actually logged on
                return await this.loginWithUser(user, false, event);
            }

            return {
                success: true,
                formData: formData,
            };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't change password");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        }
    }

    /**
     * Call this to delete the logged-in user
     * 
     * @param event the Sveltekit event.  

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     */
    async deleteUser(event : RequestEvent) : Promise<DeleteUserReturn> {
        CrossauthLogger.logger.debug(j({msg:"deleteUser"}));
        try {

            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }
        
            // throw an error if not logged in
            if (!event.locals.user) {
                throw new CrossauthError(ErrorCode.InsufficientPriviledges);
            }

            await this.sessionServer.userStorage.deleteUserById(event.locals.user.id);
            event.cookies.delete(this.sessionServer.sessionManager.sessionCookieName, {path: "/"});
            event.locals.sessionId = undefined;
            event.locals.user = undefined;
            return {
                success: true,

            };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't delete account");
            return {
                error: ce.message,
                exception: ce,
                success: false,
            }
        }
    }

    /**
     * Call this to update a user's details (apart from password and factor2)
     * 
     * @param event the Sveltekit event.  The form fields used are
     *   - `username` the desired username
     *   - `user_*` anything prefixed with `user` that is also in
     *   - the `userEditableFields` option passed when constructing the
     *     user storage object will be added to the {@link @crossuath/common!User}
     *     object (with `user_` removed).
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `emailVerificationRequired` if true, the user needs to click on
     *     the link emailed to them to complete signup.
     */
    async updateUser(event : RequestEvent) : Promise<UpdateUserReturn> {
        CrossauthLogger.logger.debug(j({msg:"updateUser"}));
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }
    
            // throw an error if not logged in
            if (!event.locals.user) {
                throw new CrossauthError(ErrorCode.InsufficientPriviledges);
            }
            
            // get new user fields from form, including from the 
            // implementor-provided hook
            let user : User = {
                id: event.locals.user.id,
                username: event.locals.user.username,
                state: "active",
            };
            user = this.sessionServer.updateUserFn(user,
                event,
                formData,
                this.sessionServer.userStorage.userEditableFields);

            // validate the new user using the implementor-provided function
            let errors = this.sessionServer.validateUserFn(user);
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.FormEntry, errors);
            }

            // update the user
            let emailVerificationNeeded = 
                await this.sessionServer.sessionManager.updateUser(event.locals.user, user);
            if (!emailVerificationNeeded) {
                const resp = await this.sessionServer.userStorage.getUserById(event.locals.user.id);
                event.locals.user = resp.user;
            }
            return {
                success: true,
                formData: formData,
                emailVerificationNeeded,
            };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't update account");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
                emailVerificationNeeded: false,
            }
        }
    }

    /**
     * Call this to change the logged in user's factor2.
     * 
     * @param event the Sveltekit event.  The form fields used are
     *   - `factor2` the new designed factor2, which must be in
     *     the `allowedFactor2` option passed to the constructor.
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `factor2Data` the data to pass to the factor2 configuration page.
     */
    async changeFactor2(event : RequestEvent) : Promise<ChangeFactor2Return> {
        CrossauthLogger.logger.debug(j({msg:"updateUser"}));
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }
    
            // see if the user is allowed to do this
            let username = event.locals.user?.username;
            if (!this.isSessionUser(event) || !event.locals.user) {
                // user is not logged on - check if there is an anonymous 
                // session with passwordchange set (meaning the user state
                // was set to changepasswordneeded when logging on)
                const sessionData = await this.sessionServer.getSessionData(event, "factor2change")
                if (!sessionData?.username) {
                    if (!this.isSessionUser(event)) {
                        // as we create session data, user has to be logged in with cookies
                        if (this.sessionServer.unauthorizedUrl) {
                            this.sessionServer.redirect(302, this.sessionServer.unauthorizedUrl)
                        }
                        this.sessionServer.error(401, "Unauthorized");
                    }
                }
                username = sessionData?.username;
            }
            let user = event.locals.user;
            if (!user && username) {
                const resp = await this.sessionServer.userStorage.getUserByUsername(
                    username, {
                        skipActiveCheck: true,
                        skipEmailVerifiedCheck: true,
                    });
                user = resp.user;

            }

            // throw an error if not logged in
            if (!user) {
                throw new CrossauthError(ErrorCode.InsufficientPriviledges);
            }
            
            if (!event.locals.sessionId) {
                throw new CrossauthError(ErrorCode.Unauthorized);
            }
    
            // validate the requested factor2
            let newFactor2 : string|undefined = formData.factor2;
            if (formData.factor2 && 
                !(this.sessionServer.allowedFactor2Names.includes(formData.factor2))) {
                throw new CrossauthError(ErrorCode.Forbidden,
                    "Illegal second factor " + formData.factor2 + " requested");
            }
            if (formData.factor2 == "none" || formData.factor2 == "") {
                newFactor2 = undefined;
            }

        // get data to show user to finish 2FA setup
        const userData = await this.sessionServer.sessionManager
            .initiateTwoFactorSetup(user, newFactor2, event.locals.sessionId);

            if (newFactor2) {
                return {
                    success: true,
                    formData: formData,
                    factor2Data: {
                        username: user.username,
                        factor2: newFactor2 ?? "",
                        userData,
                        csrfToken: event.locals.csrfToken,
                    }
                };    
            } 
            return {
                success: true,
                formData: formData,
            };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't update account");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        }
    }

    /**
     * Call this to reconfigure the current factor2 type.
     * 
     * @param event the Sveltekit event.  
     * 
     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *     even if factor2 authentication is required, this will still
     *     be true if there was no error.
     *   - `user` the user if login was successful
     *   - `formData` the form fields extracted from the request
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     *   - `factor2Data` the data to pass to the factor2 configuration page.
     */
    async reconfigureFactor2(event : RequestEvent) : Promise<ChangeFactor2Return> {
        CrossauthLogger.logger.debug(j({msg:"updateUser"}));
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // throw an error if the CSRF token is invalid
            if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
            }
    
            // see if the user is allowed to do this
            let username = event.locals.user?.username;
            if (!this.isSessionUser(event) || !event.locals.user) {
                // user is not logged on - check if there is an anonymous 
                // session with passwordchange set (meaning the user state
                // was set to changepasswordneeded when logging on)
                const sessionData = await this.sessionServer.getSessionData(event, "factor2change")
                if (!sessionData?.username) {
                    if (!this.isSessionUser(event)) {
                        // as we create session data, user has to be logged in with cookies
                        if (this.sessionServer.unauthorizedUrl) {
                            this.sessionServer.redirect(302, this.sessionServer.unauthorizedUrl)
                        }
                        this.sessionServer.error(401, "Unauthorized");
                    }
                }
                username = sessionData?.username;
            }
            let user = event.locals.user;
            if (!user && username) {
                const resp = await this.sessionServer.userStorage.getUserByUsername(
                    username, {
                        skipActiveCheck: true,
                        skipEmailVerifiedCheck: true,
                    });
                user = resp.user;

            }
            
            // throw an error if not logged in
            if (!user) {
                throw new CrossauthError(ErrorCode.InsufficientPriviledges);
            }
            
            if (!event.locals.sessionId) {
                throw new CrossauthError(ErrorCode.Unauthorized);
            }
    
            if (!event.locals.sessionId) {
                throw new CrossauthError(ErrorCode.Unauthorized);
            }

            // get second factor authenticator
            let factor2 : string = user.factor2;
            const authenticator = this.sessionServer.authenticators[factor2];
            if (!authenticator || authenticator.secretNames().length == 0) {
                throw new CrossauthError(ErrorCode.BadRequest, 
                    "Selected second factor does not have configuration");
            }
        
            // step one in 2FA setup - create secrets and get data to dispaly to user
            const userData = 
                await this.sessionServer.sessionManager.initiateTwoFactorSetup(user,
                    factor2,
                    event.locals.sessionId);

            return {
                success: true,
                formData: formData,
                factor2Data: {
                    username: user.username,
                    factor2: user.factor2 ?? "",
                    userData,
                    csrfToken: event.locals.csrfToken,
                }
        };

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't update account");
            return {
                error: ce.message,
                exception: ce,
                success: false,
                formData,
            }
        }
    }

    ////////////////////////////////////////////////////////////////
    // Sveltekit user endpoints

    baseEndpoint(event : RequestEvent) {
        return {
            user : event.locals.user,
            csrfToken: event.locals.csrfToken,
        }
    }

    readonly signupEndpoint : SveltekitEndpoint = {
        load: async (event : RequestEvent) => {
            let allowedFactor2 = this.sessionServer?.allowedFactor2 ??
                [{name: "none", friendlyName: "None"}];
            return {
                allowedFactor2,
                ...this.baseEndpoint(event),
            };
        },

        actions: {
            default: async ( event ) => {
                const resp = await this.signup(event);
                delete resp?.exception;
                return resp;
            }        
        }
    };

    readonly loginEndpoint : SveltekitEndpoint = {
        load: async ( event : RequestEvent ) => {
            return {
                next: "/",
                ...this.baseEndpoint(event),
            };
        },
        actions: {
            login: async ( event ) => {
                const resp = await this.login(event);
                    if (resp?.success == true && !resp?.factor2Required) 
                      this.sessionServer.redirect(302, resp.formData?.next ?? this.loginRedirectUrl);
                        if (resp && (
                            resp?.exception?.code == ErrorCode.UserNotExist ||
                            resp?.exception?.code == ErrorCode.PasswordInvalid)) {
                                resp.error = "Username or password is invalid";
                        }
                        delete resp?.exception;
                        return resp;
            },
            factor2: async ( event ) => {
                const resp = await this.loginFactor2(event);
                if (resp?.success == true && !resp?.factor2Required) this.sessionServer.redirect(302, resp.formData?.next ?? this.loginRedirectUrl);
                delete resp?.exception;
                return resp;
        
            },
        },
    };

    readonly factor2Endpoint  : SveltekitEndpoint = {
        load:  async (event) => {
            const resp = await this.requestFactor2(event);
            if (resp && !resp.error && event.url.searchParams.get("error"))
                resp.error = event.url.searchParams.get("error") ?? undefined;
            return resp;
        },
    };

    readonly logoutEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const resp = await this.logout(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            return {
                ...this.baseEndpoint(event),
            }
        },
    };

    readonly changeFactor2Endpoint  : SveltekitEndpoint = {
        actions : {
            change: async ( event ) => {
                const resp = await this.changeFactor2(event);
                delete resp?.exception;
                return resp;
            },
            reconfigure: async ( event ) => {
                const resp = await this.reconfigureFactor2(event);
                delete resp?.exception;
                return resp;
            },
        },
        load: async ( event ) => {

            let username = event.locals.user?.username;

            // see if the user is allowed to do this
            if (!this.isSessionUser(event) || !event.locals.user) {
                // user is not logged on - check if there is an anonymous 
                // session with passwordchange set (meaning the user state
                // was set to changepasswordneeded when logging on)
                const sessionData = await this.sessionServer.getSessionData(event, "factor2change")
                if (!sessionData?.username) {
                    if (!this.isSessionUser(event)) {
                        // as we create session data, user has to be logged in with cookies
                        if (this.sessionServer.unauthorizedUrl) {
                            this.sessionServer.redirect(this.sessionServer.unauthorizedUrl)
                        }
                        this.sessionServer.error(401, "Unauthorized");
                    }
                }
                username = sessionData?.username;
            }

            let allowedFactor2 = this.sessionServer.allowedFactor2 ??
                [{name: "none", friendlyName: "None", configurable: false}];
            let data : {required?: boolean, next? : string} = {};
            let requiredString = event.url.searchParams.get("required");
            let required : boolean|undefined = undefined;
            if (requiredString) {
                requiredString = requiredString.toLowerCase();
                required = requiredString == "true" || requiredString == "1";
                if (required == true) data.required = true;
            }
            let next = event.url.searchParams.get("next");
            if (next) data.next = next;
            return {
                allowedFactor2,
                ...data,
                username,
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly changePasswordEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const resp = await this.changePassword(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            let data : {required?: boolean, next? : string} = {};
            let requiredString = event.url.searchParams.get("required");
            let required : boolean|undefined = undefined;
            let haveUser = event.locals.user != undefined;
            if (!haveUser) {
                const passwordchange = await this.sessionServer.getSessionData(event, "passwordchange");
                if (passwordchange?.username) haveUser = true;
            }
            if (!haveUser) this.sessionServer.redirect(302, this.loginUrl)
            if (requiredString) {
                requiredString = requiredString.toLowerCase();
                required = requiredString == "true" || requiredString == "1";
                if (required == true) data.required = true;
            }
            let next = event.url.searchParams.get("next");
            if (next) data.next = next;
            return {
                ...data,
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly configureFactor2Endpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const resp = await this.configureFactor2(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            return {
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly deleteUserEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const resp = await this.deleteUser(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            return {
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly resetPasswordEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const resp = await this.requestPasswordReset(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            let data : {required?: boolean, next? : string} = {};
            let requiredString = event.url.searchParams.get("required");
            let required : boolean|undefined = undefined;
            if (requiredString) {
                requiredString = requiredString.toLowerCase();
                required = requiredString == "true" || requiredString == "1";
                if (required == true) data.required = true;
            }
            return {
                ...data,
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly passwordResetTokenEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
        
                // we already visited this URL and used it to initiate 2FA
                // - execute as normal to perform password reset
                const resp = await this.resetPassword(event);
                delete resp?.exception;
                return resp;    
            }
        },
        load: async ( event ) => {
            try {
                const resp = await this.validatePasswordResetToken(event);
                if (!resp?.user) throw new CrossauthError(ErrorCode.InvalidToken, "The password reset token is invalid");
                if (resp.user.factor2 != "" && !event.locals.sessionId) {
                    // If we have 2FA, we need to create an anonymous session with
                    // user.username set for the 2FA hook to pick up the 2FA config
                    await this.sessionServer.createAnonymousSession(event, {user: {username: resp.user.username}});
                }
                return {
                    tokenValidated: resp?.success ?? false,
                    error: resp?.error,
                    ...this.baseEndpoint(event),
                };    
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({cerr: ce}));
                return {
                    tokenValidated: false,
                    error: ce.message,
                    ...this.baseEndpoint(event),
                };    
            }
        },
    };

    readonly updateUserEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) =>  {
                const resp = await this.updateUser(event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            //this.sessionServer?.refreshLocals(event);
            let allowedFactor2 = this.sessionServer.allowedFactor2 ??
            [{name: "none", friendlyName: "None"}];
            return {
                allowedFactor2,
                ...this.baseEndpoint(event),
            };
        }
    };

    readonly verifyEmailTokenEndpoint  : SveltekitEndpoint = {
        load: async ( event ) => {
            const resp = await this.verifyEmail(event);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
    };
}