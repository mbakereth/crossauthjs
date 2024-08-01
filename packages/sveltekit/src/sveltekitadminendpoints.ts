import { SvelteKitServer } from './sveltekitserver';
import { SvelteKitSessionServer } from './sveltekitsession';
import type { SvelteKitSessionServerOptions, SveltekitEndpoint } from './sveltekitsession';
import { TokenEmailer } from '@crossauth/backend';
import type { UserStorage, AuthenticationParameters } from '@crossauth/backend';
import type { User, UserInputFields } from '@crossauth/common';
import { CrossauthError, CrossauthLogger, j, ErrorCode, UserState } from '@crossauth/common';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type AdminUpdateUserReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    success: boolean,
};

export type AdminChangePasswordReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    formData?: {[key:string]:string},
    success: boolean
};

export type AdminCreateUserReturn = {
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
};

export type ADminDeleteUserReturn = {
    user? : User,
    error?: string,
    exception?: CrossauthError,
    success: boolean
};

export type SearchUsersReturn = {
    success : boolean,
    users?: User[],
    skip : number,
    take : number,
    search? : string,
    error? : string,
    exception?: CrossauthError,
    hasPrevious : boolean,
    hasNext : boolean,
};

async function defaultUserSearchFn(searchTerm: string,
    userStorage: UserStorage, skip = 0, _take = 10) : Promise<User[]> {
        let users : User[] = [];
    if (skip > 0) return [];
    try {
        const {user} = 
            await userStorage.getUserByUsername(searchTerm);
            users.push(user);
    } catch (e1) {
        const ce1 = CrossauthError.asCrossauthError(e1);
        if (ce1.code != ErrorCode.UserNotExist) {
            CrossauthLogger.logger.debug(j({err: ce1}));
            throw ce1;
        }
        try {
            const {user} = 
                await userStorage.getUserByEmail(searchTerm);
                users.push(user);
        } catch (e2) {
            const ce2 = CrossauthError.asCrossauthError(e2);
            if (ce2.code != ErrorCode.UserNotExist) {
                CrossauthLogger.logger.debug(j({err: ce2}));
                throw ce1;
            }
        }
    }
    return users;

}

/**
 * Provides endpoints for users to login, logout and maintain their 
 * own account.
 * 
 * This class is not intended to be used outside of Crossauth.  For 
 * documentation about functiuons it provides, see
 * {@link SvelteKitSessionServer}.
 */
export class SvelteKitAdminEndpoints {
    private sessionServer : SvelteKitSessionServer;
    private userSearchFn : 
        (searchTerm : string, userStorage : UserStorage, skip? : number, take? : number) => Promise<User[]> =
        defaultUserSearchFn;

    constructor(sessionServer : SvelteKitSessionServer,
        options : SvelteKitSessionServerOptions
    ) {
        this.sessionServer = sessionServer;
        if (options.userSearchFn) this.userSearchFn = options.userSearchFn
    }

    /** Returns whether there is a user logged in with a cookie-based session
     */
    isSessionUser(event: RequestEvent) {
        return event.locals.user != undefined && event.locals.authType == "cookie";
    }
    
    /**
     * Returns either a list of all users or users matching a search term.
     * 
     * The returned list is pagenaed using the `skip` and `take` parameters.
     * 
     * The searching is done with `userSearchFn` that was passed in the
     * options (see {@link SvelteKitSessionServerOptions }).  THe default
     * is an exact username match.
     * 
     * By default, the searh and pagination parameters are taken from 
     * the query parameters in the request but can be overridden.
     * 
     * @param event the Sveltekit request event.  The following query parameters
     *        are read:
     *   - `search` the search term which is ignored if it is undefined, null
     *      or the empty string.
     *   - `skip` the number to start returning from.  0 if not defined
     *   - `take` the maximum number to return.  10 if not defined.
     * @param search overrides the search term from the query.
     * @param skip overrides the skip term from the query
     * @param take overrides the take term from the query
     * 
     * @return an object with the following members:
     *   - `success` true or false depending on whether there was an error
     *   - `users` the matching array of users
     *   - `error` error message if `success` is false
     *   - `exception` a {@link @crossauth/common!CrossauthError} if there was
     *      an error.
     *   - `search` the search term that was used
     *   - `skip` the skip term that was used
     *   - `take` the take term that was used
     *   - `hasNext` whether there are still more results after the ones that
     *      were returned
     *   - `hasPrevious` whether there are more results before the ones that
     *      were returned.
     */
    async searchUsers(event : RequestEvent, searchTerm? : string, skip? : number, take? : number)
        : Promise<SearchUsersReturn> {

        try {

        // can only call this if logged in as admin
        if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) {
            this.sessionServer.error(401);
        }

        let users : User[] = [];
            let prevUsers : User[] = [];
            let nextUsers : User[] = [];
            if (!skip) {
                try {
                    const str = event.url.searchParams.get("skip");
                    if (str) skip = parseInt(str);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({cerr: e, msg: "skip parameter is not an integer"}))
                }
    
            }
            if (!skip) skip = 0;
            if (!take) {
                try {
                    const str = event.url.searchParams.get("take");
                    if (str) take = parseInt(str);
                } catch (e) {
                    CrossauthLogger.logger.warn(j({cerr: e, msg: "take parameter is not an integer"}))
                }
            }
            if (!take) take = 10;
        
            const searchFromUrl = event.url.searchParams.get("search");
            if (!searchTerm && searchFromUrl != null && searchFromUrl != "") 
                searchTerm = searchFromUrl;
            if (!searchTerm) searchTerm = "";
            if (searchTerm.length == 0) searchTerm = undefined;
            
            if (searchTerm) {
                users = await this.userSearchFn(searchTerm, 
                    this.sessionServer.userStorage, skip, take);
                if (skip > 0) {
                    prevUsers = await this.userSearchFn(searchTerm, 
                        this.sessionServer.userStorage, skip-1, 1);

                }
                } else {
                    users = 
                        await this.sessionServer.userStorage.getUsers(skip, 
                            take);
                    if (users.length == take) {
                        nextUsers = 
                            await this.sessionServer.userStorage.getUsers(skip+take, 
                                1);

                    }
                }

            return {
                success: true,
                users,
                skip,
                take,
                hasPrevious: prevUsers.length > 0,
                hasNext: nextUsers.length > 0,
                search: searchTerm
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            return {
                success: false,
                error: ce.message,
                exception: ce,
                hasPrevious: false,
                hasNext : false,
                skip: skip ?? 0, 
                take: take ?? 10,
                search: searchTerm,
            }
        }

    }

    async updateUser(user : User, event: RequestEvent) {

        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // can only call this if logged in as admin
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) {
                this.sessionServer.error(401);
            }

            // CSRF token must be valid if we are using them
            if (this.isSessionUser(event) && this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);

            const oldFactor2 = user.factor2;
            const oldState = user.state;
            user.state = formData.state ?? "active";
            user = this.sessionServer.updateUserFn(user,
                event,
                formData,
                {...this.sessionServer.userStorage.userEditableFields,
                    ...this.sessionServer.userStorage.adminEditableFields});
            const factor2ResetNeeded = user.factor2 && user.factor2 != "none" && user.factor2 != oldFactor2;
            if (factor2ResetNeeded && !(user.state == oldState || user.state == "factor2ResetNeeded")) {
                throw new CrossauthError(ErrorCode.BadRequest, "Cannot change both factor2 and state at the same time");
            }
            if (factor2ResetNeeded) {
                user.state = UserState.factor2ResetNeeded;
                CrossauthLogger.logger.warn(j({msg: `Setting state for user to ${UserState.factor2ResetNeeded}`, 
                username: user.username}));
            } 
        
            // validate the new user using the implementor-provided function
            let errors = this.sessionServer.validateUserFn(user);
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.FormEntry, errors);
            }

            // update the user
            await this.sessionServer.sessionManager.updateUser(user, user, true);

            return {
                success: true,
                formData: formData,
            };

        } catch (e) {
            // let Sveltekit redirect and 401 error through
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e, 401)) throw e;

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
     * Call this with POST data to change the logged-in user's password
     * 
     * @param user the user to edit
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
    async changePassword(user : User, event : RequestEvent) : Promise<AdminChangePasswordReturn> {
        CrossauthLogger.logger.debug(j({msg:"changePassword"}));
        let formData : {[key:string]:string}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();

            // can only call this if logged in as admin
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) {
                this.sessionServer.error(401);
            }

            //this.validateCsrfToken(request)
            if (this.isSessionUser(event) && 
                this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                throw new CrossauthError(ErrorCode.InvalidCsrf);
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
            try {
                await this.sessionServer.sessionManager.changeSecrets(user.username,
                    1,
                    newSecrets,
                    repeatSecrets,
                    oldSecrets
                );
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: e}));
                throw ce; 
            }
    
            return {
                success: true,
                formData: formData,
            };

        } catch (e) {
            // let Sveltekit redirect and 401 error through
            if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
            if (SvelteKitServer.isSvelteKitError(e, 401)) throw e;

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
    async createUser(event : RequestEvent) : Promise<AdminCreateUserReturn> {

        let formData : {[key:string]:string|undefined}|undefined = undefined;
        try {
            // get form data
            var data = new JsonOrFormData();
            await data.loadData(event);
            formData = data.toObject();
            const username = data.get('username') ?? "";
            let user : UserInputFields|undefined;

            // can only call this if logged in as admin
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) {
                this.sessionServer.error(401);
            }
            
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
                this.sessionServer.createUserFn(event, formData, 
                    {...this.sessionServer.userStorage.userEditableFields,
                    ...this.sessionServer.userStorage.adminEditableFields});

            const secretNames = this.sessionServer.authenticators[user.factor1].secretNames();
            let hasSecrets = true;
            for (let secret of secretNames) {
                if (!formData[secret] && !formData["repeat_"+secret]) hasSecrets = false;
            }
            // ask the authenticator to validate the user-provided secret
            let passwordErrors : string[] = [];
            let repeatSecrets : AuthenticationParameters|undefined = {};
            if (hasSecrets) {
                passwordErrors = this.sessionServer.authenticators[user.factor1].validateSecrets(formData);
                // get the repeat secrets (secret names prefixed with repeat_)
                for (let field in formData) {
                    if (field.startsWith("repeat_")) {
                        const name = field.replace(/^repeat_/, "");
                        // @ts-ignore as it complains about request.body[field]
                        if (secretNames.includes(name)) repeatSecrets[name] = 
                        formData[field];
                    }
                }
                if (Object.keys(repeatSecrets).length === 0) repeatSecrets = undefined;
            }

            // If a password wasn't given, force the user to do a passowrd
            // reset on login
            if (!hasSecrets) {
                if (formData.factor2 == undefined) user.state =UserState.passwordResetNeeded;
                else user.state =UserState.passwordAndFactor2ResetNeeded;
            } else if (formData.factor2 != undefined) user.state =UserState.factor2ResetNeeded;

            // call the implementor-provided hook to validate the user fields
            let userErrors = this.sessionServer.validateUserFn(user);
            // report any errors
            let errors = [...userErrors, ...passwordErrors];
            if (errors.length > 0) {
                throw new CrossauthError(ErrorCode.FormEntry, errors);
            }

            const newUser = await this.sessionServer.sessionManager.createUser(user,
                formData, repeatSecrets, true, !hasSecrets);
    
            if (!hasSecrets) {
                let email = formData.username;
                if ("user_email" in formData) email = formData.user_email;
                TokenEmailer.validateEmail(email);
                if (!email) throw new CrossauthError(ErrorCode.FormEntry, "No password given but no email address found either");
                await this.sessionServer.sessionManager.requestPasswordReset(email);
            }
            
            return { success: true, user: newUser,  formData};

        } catch (e) {
            let ce = CrossauthError.asCrossauthError(e, "Couldn't create user");
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
     * @param userId the user to delete
     * @param event the Sveltekit event.  

     * @returns object with:
     * 
     *   - `success` true if creation and login were successful, 
     *      false otherwise.
     *   - `error` an error message or undefined
     *   - `exception` a {@link @crossauth/common!CrossauthError} if an
     *     exception was raised
     */
        async deleteUser(event : RequestEvent) : Promise<ADminDeleteUserReturn> {
            CrossauthLogger.logger.debug(j({msg:"deleteUser"}));
            try {
    
                const userId = event.params.id;
                if (!userId) throw new CrossauthError(ErrorCode.BadRequest, "User ID is undefined");

                // throw an error if the CSRF token is invalid
                if (this.sessionServer.enableCsrfProtection && !event.locals.csrfToken) {
                    throw new CrossauthError(ErrorCode.InvalidCsrf);
                }
            
                // can only call this if logged in as admin
                if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) {
                    this.sessionServer.error(401);
                }
    
                await this.sessionServer.userStorage.deleteUserById(userId);
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
    
    
    ///////////////////////////////////////////////////////////////////
    // endpoints 

    baseEndpoint(event : RequestEvent) {
        return {
            user : event.locals.user,
            csrfToken: event.locals.csrfToken,
        }
    }

    readonly searchUsersEndpoint  : SveltekitEndpoint = {
        load: async ( event ) => {
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) this.sessionServer.error(event, 401);
            const resp = await this.searchUsers(event);
            delete resp?.exception;
            return {
                ...this.baseEndpoint(event),
                ...resp,
            };
        },
    };

    private async getUserFromParam(event : RequestEvent, paramName="id") : Promise<{user? : User, exception? : CrossauthError}> {
        let userId = event.params[paramName];
        if (!userId) {
            return {exception: new CrossauthError(ErrorCode.BadRequest, "Must give user id")};

        }
        try {
            const resp = await this.sessionServer.userStorage.getUserById(userId);
            return {user: resp.user};
        } catch (e) {
            return {exception: CrossauthError.asCrossauthError(e)};
        }
    }

    readonly updateUserEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) =>  {
                const getUserResp = await this.getUserFromParam(event);
                if (getUserResp.exception || !getUserResp.user) {
                    return {
                        success: false,
                        error: getUserResp.exception?.message ?? "Couldn't get user",
                    }
                }
                const resp = await this.updateUser(getUserResp.user, event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) this.sessionServer.error(event, 401);
            let allowedFactor2 = this.sessionServer.allowedFactor2 ??
                [{name: "none", friendlyName: "None"}];
            const getUserResp = await this.getUserFromParam(event);
            if (getUserResp.exception || !getUserResp.user) {
                return {
                    allowedFactor2,
                    editUser: getUserResp.user,
                    ...this.baseEndpoint(event),
                }
            }
            //this.sessionServer?.refreshLocals(event);
            return {
                allowedFactor2,
                editUser: getUserResp.user,
                ...this.baseEndpoint(event),
            };
        }
    };

    readonly changePasswordEndpoint  : SveltekitEndpoint = {
        actions : {
            default: async ( event ) => {
                const getUserResp = await this.getUserFromParam(event);
                if (getUserResp.exception || !getUserResp.user) {
                    return {
                        success: false,
                        error: getUserResp.exception?.message ?? "Couldn't get user",
                    }
                }
                const resp = await this.changePassword(getUserResp.user, event);
                delete resp?.exception;
                return resp;
            }
        },
        load: async ( event ) => {
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) this.sessionServer.error(event, 401);
            const getUserResp = await this.getUserFromParam(event);
            if (getUserResp.exception || !getUserResp.user) {
                return {
                    editUser: getUserResp.user,
                    ...this.baseEndpoint(event),
                }
            }
            let data : {next? : string} = {};
            let next = event.url.searchParams.get("next");
            if (next) data.next = next;
            return {
                ...data,
                editUser: getUserResp.user,
                ...this.baseEndpoint(event),
            };
        },
    };

    readonly createUserEndpoint : SveltekitEndpoint = {
        load: async (event : RequestEvent) => {
            if (!event.locals.user || !SvelteKitServer.isAdminFn(event.locals.user)) this.sessionServer.error(event, 401);
            let allowedFactor2 = this.sessionServer?.allowedFactor2 ??
                [{name: "none", friendlyName: "None"}];
            return {
                allowedFactor2,
                ...this.baseEndpoint(event),
            };
        },

        actions: {
            default: async ( event ) => {
                const resp = await this.createUser(event);
                delete resp?.exception;
                return resp;
            }        
        }
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
            const getUserResp = await this.getUserFromParam(event);
            if (getUserResp.exception || !getUserResp.user) {
                return {
                    error: "User doesn't exist",
                    ...this.baseEndpoint(event),
                }
            }
            return {
                username: getUserResp.user?.username,
                ...this.baseEndpoint(event),
            };
        },
    };
}

