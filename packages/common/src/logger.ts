// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

import { ErrorCode, CrossauthError } from "./error";
/**
 * You can implement your own logger.  Crossauth only needs these functions
 * and variables to be present.
 */
export interface CrossauthLoggerInterface {
    error(output: any) : void;
    warn(output: any) : void;
    info(output: any) : void;
    debug(output: any) : void;
    level? : number|string;
}

/**
 * 
 * A very simple logging class with no dependencies.
 * 
 * Logs to console. 
 * 
 * The logging API is designed so that you can replace this with other common loggers, eg Pino.
 * To change it, use the global {@link setLogger} function.  This has a parameter to tell 
 * Crossauth whether your logger accepts JSON input or not.
 * 
 * When writing logs, we use the helper function {@link j} to send JSON to the logger if it is
 * supprted, and a stringified JSON otherwise.
 * 
 * <b>Crossauth logs<b>
 * 
 * All Crossauth log messages are JSON (or stringified JSON, depending on whether the logger supports
 * JSON input - this one does).  The following fields may be present depending on context
 * (`message` is always present):
 * 
 * - `message` : main contents of the log
 * - `err` : an error object.  If a subclass of Error, it wil contain at least `message` and
 *           a stack trace in `stack`.  If the error is of type {@link @crossauth/common!CrossauthError} 
 *           it also will also contain `code` and `httpStatus`.
 * - `hashedSessionCookie` : for security reasons, session cookies are not included in logs.
 *                           However, so that errors can be correlated with each other, a hash
 *                           of it is included in errors originating from a session.
 * - `hashedCsrfCookie`    : for security reasons, csrf cookies are not included in logs.
 *                           However, so that errors can be correlated with each other, a hash
 *                           of it is included in errors originating from a session.
 * - `user` : username
 * - `emailMessageId` : internal id of any email that is sent
 * - `email` : email address
 * - `userid` : sometimes provided in addition to username, or when username not available
 * - `hashedApiKey` : a hash of an API key.  The unhashed version is not logged for security,
 *                   but a hash of it is logged for correlation purposes.
 * - `header`      : an HTTP header that relates to an error (eg `Authorization`), only if
 *                   it is non-secret or invalid
 * - `accessTokenHash` : hash of the JTI of an access token.  For security reasons, the 
 *                       unhashed version is not logged.
 * - `method`: request method (GET, PUT etc)
 * - `url` : relevant URL
 * - `ip`  : relevant IP address           
 * - `scope` : OAuth scope
 * - `errorCode` : Crossauth error code
 * - `errorCodeName` : String version of Crossauth error code
 * - `httpStatus` : HTTP status that will be returned
 * - `port` port service is running on (only for starting a service)
 * - `prefix` prefix for endpoints (only when starting a service)
 * - `authorized` whether or not a valid OAuth access token was provided
 * 
 */
export class CrossauthLogger {


    /** Don't log anything */
    static readonly None = 0;

    /** Only log errors */
    static readonly Error = 1;

    /** Log errors and warning */
    static readonly Warn = 2;

    /** Log errors, warnings and info messages */
    static  readonly Info = 3;

    /** Log everything */
    static readonly Debug = 4; 

    /**
     * Return the singleton instance of the logger.
     * @returns the logger
     */
    static get logger() : CrossauthLoggerInterface { 
        /*if (!CrossauthLogger.instance) {
            CrossauthLogger.instance = new CrossauthLogger(CrossauthLogger.None);
        }
        return CrossauthLogger.instance;*/
        return globalThis.crossauthLogger;
    }

    /** the log level. This can be set dynamically */
    level : 0 | 1 | 2 | 3 | 4;
    static levelName = ["NONE", "ERROR", "WARN", "INFO", "DEBUG"];
    static ecsLevelName = ["none", "error", "warn", "info", "debug"];

    static extraFields: {[key:string]:any} = {}

    static logAsEcs = false;

    /**
     * Create a logger with the given level
     * @param level the level to report to
     */
    constructor(level?: 0 | 1 | 2 | 3 | 4) {
        if (level) this.level = level;
        else if (typeof process !== 'undefined' && process?.env.CROSSAUTH_LOG_LEVEL) {
            const levelName = (process.env.CROSSAUTH_LOG_LEVEL??"ERROR").toUpperCase();
            if (CrossauthLogger.levelName.includes(levelName)) {
                // @ts-ignore
                this.level = CrossauthLogger.levelName.indexOf(levelName);
            } else {
                this.level = CrossauthLogger.Error
            }
        } else {
            this.level = CrossauthLogger.Error;
        }
    }

    setLevel(level: 0 | 1 | 2 | 3 | 4) {
        this.level = level;
    }

    static setExtraFields(extraFields: {[key:string]:any}) {
        CrossauthLogger.extraFields = {...extraFields}
    }

    static setLogAsEcs(value: boolean) {
        CrossauthLogger.logAsEcs = value;
    }

    private toEcs(level: 0 | 1 | 2 | 3 | 4, input: {[key:string]:any}) : any {
        input["log.level"] = CrossauthLogger.ecsLevelName[level]; delete input.level;
        input["@timestamp"] = input.time; delete input.time;
        input["log.logger"] = "CrossauthLogger";
        if (input.method) {
            input["http.request.method"] = input.method;
            delete input.method
        }
        if (input.responseCode) {
            input["http.response.status_code"] = input.responseCode;
            delete input.responseCode
        }
        if (input.ip) {
            input["client.address"] = input.ip;
            input["client.ip"] = input.ip;
            delete input.ip
        }
            if (input.url) {
            input["url.original"] = input.url;
            delete input.url
        }

        if (input.email) {
            input["user.email"] = input.email;
            delete input.email
        }
        if (input.user) {
            input["user.name"] = input.user;
            delete input.user
        }
        if (input.userid) {
            input["user.id"] = input.userid;
            delete input.userid
        }
        if (input.targetUser) {
            input["crossauth.target.user.name"] = input.targetUser;
            delete input.targetUser
        }
        if (input.targetUserid) {
            input["crossauth.target.user.id"] = input.targetUserid;
            delete input.targetUserid
        }
        if (input.actionCodeName) {
            input["crossauth.actioncode"] = input.actionCodeName;
            delete input.actionCodeName
            if (input.actionCode) delete input.actionCode;
        }
        if (input.errorMessage) {
            input["error.message"] = input.errorMessage;
            delete input.errorMessage;
            if (input.errorMessages) delete  input.errorMessages
        } else if (input.message && input.errorCode) {
            input["error.message"] = input.message;
            delete input.message;
            if (input.messages) delete input.messages;
        }
        if (input.errorCodeName) {
            input["error.code"] = input.errorCodeName;
            delete input.errorCodeName;
            if (input.errorCode) delete  input.errorCode
        } 
        if (input.stack) {
            input["error.stack"] = input.stack;
            delete input.stack;
        } 

        return input

    }

    private log(level: 0 | 1 | 2 | 3 | 4 , output: {[key:string]:any}|string) {
        if (level <= this.level) {
            if (typeof output == "string") {
                console.log("Crossauth " + CrossauthLogger.levelName[level] + " " + new Date().toISOString(), output);
            } else {
                console.log(JSON.stringify(this.toEcs(level, {...CrossauthLogger.extraFields, level: CrossauthLogger.levelName[level], time: new Date().toISOString(), ...output})));
            }
        }
    }

    /**
     * Report an error
     * @param output object to output
     */
    error(output: any) {
        this.log(CrossauthLogger.Error, output);
    }

    /**
     * Report an warning
     * @param output object to output
     */
    warn(output: any) {
        this.log(CrossauthLogger.Warn, output);
    }

    /**
     * Report information
     * @param output object to output
     */
    info(output: any) {
        this.log(CrossauthLogger.Info, output);
    }

    /**
     * Print a debugging message
     * @param output object to output
     */
    debug(output: any) {
        this.log(CrossauthLogger.Debug, output);
    }

    /** 
     * Override the default logger.
     * 
     * The only requirement is that the logger has the functions `error()`, `warn()`, `info()` and `debug()`.
     * These functions must accept either an object or a string.  If they can only accept a string,
     * set `acceptsJson` to false.  
     * 
     * @param logger a new logger instance of any supported class
     * @param acceptsJson set this to false if the logger can only take strings.
     */
    static setLogger(logger : CrossauthLoggerInterface, acceptsJson : boolean) {
        globalThis.crossauthLogger = logger;
        globalThis.crossauthLoggerAcceptsJson = acceptsJson;
    }
}

/**
 * This is a helper function to allow you to use logger that either do or
 * do not accept.  
 * 
 * If your logger does accept JSON (as defined in 
 * `globalThis.crossauthLoggerAcceptsJson`), this will return the object
 * that was passed, including the stack trace in `stack` if the object
 * passed in `err` is an exception.  Otherwise, it returns a stringified
 * version.
 * 
 * All Crossauth error calls are made with this helper.
 * 
 * @param arg put the key/value pairs you want to log in here.  `err` will
 *        be treated as an `Error` instance if it is one, and a stack trace
 *        will be placed in `stack`.
 * @returns either an object or a stringified JSON, depending on
 *          `globalThis.crossauthLoggerAcceptsJson`.
 */
export function j(arg : {[key: string]: any}|string) : string|{[key: string]: any} {
    let stack;
    if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object")) {
        stack = arg.err.stack;
    }
    try {if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object") && arg.err && ("message" in arg.err) && !("message" in arg)) arg["message"] = arg.err.message;} catch {}
    try {if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object")) arg.err = {...arg.err, stack: stack}; } catch {}
    try {if (typeof arg == "object" && ("err" in arg) && !("message" in arg)) arg["message"] = arg.message = "An unknown error occurred";} catch {}
    try {if (typeof arg == "object" && ("cerr" in arg) && ("isCrossauthError" in arg.cerr) && arg.cerr ) {arg["errorCode"] = arg.cerr.code; arg["errorCodeName"] = arg.cerr.codeName; arg["httpStatus"] = arg.cerr.httpStatus; if (!("message" in arg)) arg["message"] = arg.cerr.message; if (!("errorMessage" in arg)) arg["errorMessageßß"] = arg.cerr.message; delete arg.cerr;}} catch {}
    return (typeof arg == "string" || globalThis.crossauthLoggerAcceptsJson) ? arg : JSON.stringify(arg);
}

declare global {
    var crossauthLogger : CrossauthLoggerInterface;
    var crossauthLoggerAcceptsJson : boolean;
};

/** Initialized with an instance of {@link CrossauthLogger} 
 * but you can override it with any class implementing
 * {@link CrossauthLoggerInterface}.
 * 
 * Rather than setting this directly, call
 * {@link CrossauthLogger.setLogger()}.
 */
globalThis.crossauthLogger = new CrossauthLogger();

/**
 * If your logger object accepts JSON input, set this to true.
 * 
 * Rather than setting this directly, call
 * {@link CrossauthLogger.setLogger()}.
 */
globalThis.crossauthLoggerAcceptsJson = true;

/**
 * Used when logging user-instigated actions
 */
export enum LoggedActionCode {

    /** A user attempted to log in */
	Login = 0,

    /** A user attempted to log out */
	Logout = 1,

    /** User attempted to log in when they have not verified their email */
    LoginWithoutEmailVerification = 2,

    /** User got redirected to mandatory password change*/
    PasswordChangeRedirect = 3,

    /** User logged in when password reset is needed */
    LoginWhenPasswordResetNeeded = 4,

    /** User logged in when factor2 reset is needed */
    LoginWhenFactor2ResetNeeded = 5,

    /** User logged in when password and factor2 reset is needed */
    LoginWhenPasswordAndFactor2ResetNeeded = 6,

    /** Email verification message sent */
    EmailVerificationTokenSent = 7,

    /** Email verified */
    EmailVerificationTokenComplete = 8,

    /** Invalid session or CSRF cookie */
    InvalidCookieOrToken = 9,

    /** User visited page they do not have permission to */
    UnauthorizedPageOrAPICall = 10,

    /** User attempted OAuth authorization */
    OAuthAuthorize = 11,

    /** A user attempted to change his or her password */
	PasswordChange = 102,

    /** A user attempted to get a password reset token */
	StartPasswordReset = 103,

    /** A user attempted to get a reset password using the token */
	FinishPasswordReset = 104,

    /** A user attempted to get a change their factor2 */
	ChangeFactor2 = 105,

    /** A user attempted to get a reset their factor2 */
	ResetFactor2 = 106,

    /** A user attempted to update their account */
	UpdateUser = 107,

    /** A user attempted to delete their account */
	DeleteUser = 108,

    /** A user attempted to create an ApiKey */
	CreateApiKey = 109,

    /** A user attempted to delete an ApiKey */
	DeleteApiKey = 110,

    /** A user attempted to update an ApiKey */
	UpdateApiKey = 111,

    /** A user attempted to create an OAuthClient */
	CreateOAuthClient = 112,

    /** A user attempted to delete an OAuthClient */
	DeleteOAuthClient = 113,

    /** A user attempted to update an OAuthClient */
	UpdateOAuthClient = 114,

    /** A user attempted signup */
	CreateUser = 115,

    /** A user attempted to get a configure their factor2 */
	ConfigureFactor2 = 116,

    /** Admin attempted to change user's password */
	AdminPasswordChange = 202,

    /** Admin attempted to get a password reset token for a user */
	AdminStartPasswordReset = 203,

    /** Admin attempted to get a change user's factor2 */
	AdminChangeFactor2 = 205,

    /** Admin attempted to get a reset user's factor2 */
	AdminResetFactor2 = 206,

    /** Admin attempted to update user's account */
	AdminUpdateUser = 207,

    /** Admin attempted to delete user's account */
	AdminDeleteUser = 208,

    /** Admin attempted to create an ApiKey for a user */
	AdminCreateApiKey = 209,

    /** Admin attempted to delete a user's ApiKey */
	AdminDeleteApiKey = 210,

    /** Admin attempted to update a user's ApiKey */
	AdminUpdateApiKey = 211,

    /** Admin attempted to create an OAuthClient for a user */
	AdminCreateOAuthClient = 212,

    /** Admin attempted to delete a user's OAuthClient */
	AdminDeleteOAuthClient = 213,

    /** Admin attempted to update a user's OAuthClient */
	AdminUpdateOAuthClient = 214,

    /** Admin attempted to create a user */
    AdminCreateUser = 215,

    /** Admin attempted to get a configure user's factor2 */
	AdminConfigureFactor2 = 216,
}

export function loggedActionCode(code: LoggedActionCode): {actionCode: number, actionCodeName: string} {
    return {actionCode: code, actionCodeName: LoggedActionCode[code]}
}

export function logAsWarnOrError(ce: CrossauthError, message: string|{[key:string]:any}) {
    if ([
        ErrorCode.InvalidCsrf,
        ErrorCode.UserNotExist,
        ErrorCode.UserNotActive,
        ErrorCode.InvalidKey,
        ErrorCode.InvalidToken,
        ErrorCode.Forbidden,
        ErrorCode.PasswordFormat,
        ErrorCode.PasswordInvalid,
        ErrorCode.PasswordMatch,
        ErrorCode.Forbidden,
        ErrorCode.Expired,
        ErrorCode.ExpiredToken,
    ].includes(ce.code)) {
        // user did something illegal
        CrossauthLogger.logger.warn(message)
    } else {
        // Something else
        CrossauthLogger.logger.error(message)
    }

}
