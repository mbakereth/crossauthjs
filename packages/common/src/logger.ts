import { CrossauthError } from ".";

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
 * (`msg` is always present):
 * 
 * - `msg` : main contents of the log
 * - `err` : an error object.  If a subclass of Error, it wil contain at least `message` and
 *           a stack trace in `stack`.  If the error is of type{@link CrossauthError} 
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
 * - `userId` : sometimes provided in addition to username, or when username not available
 * - `hahedApiKey` : a hash of an API key.  The unhashed version is not logged for security,
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

    /**
     * Create a logger with the given level
     * @param level the level to report to
     */
    constructor(level?: 0 | 1 | 2 | 3 | 4) {
        if (level) this.level = level;
        else if ("CROSSAUTH_LOG_LEVEL" in process.env) {
            const levelName = (process.env["CROSSAUTH_LOG_LEVEL"]??"ERROR").toUpperCase();
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

    private log(level: 0 | 1 | 2 | 3 | 4 , output: any) {
        if (level <= this.level) {
            if (typeof output == "string") {
                console.log("Crossauth " + CrossauthLogger.levelName[level] + " " + new Date().toISOString(), output);
            } else {
                console.log(JSON.stringify({level: CrossauthLogger.levelName[level], time: new Date().toISOString(), ...output}));
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

    warn(output: any) {
        this.log(CrossauthLogger.Warn, output);
    }

    info(output: any) {
        this.log(CrossauthLogger.Info, output);
    }

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

export function j(arg : {[key: string]: any}|string) : string|{[key: string]: any} {
    let stack;
    if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object")) {
        stack = arg.err.stack;
    }
    try {if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object") && arg.err && ("message" in arg.err) && !("msg" in arg)) arg["msg"] = arg.err.message;} catch {}
    try {if (typeof arg == "object" && ("err" in arg) && (typeof arg.err == "object")) arg.err = {...arg.err, stack: stack}; } catch {}
    try {if (typeof arg == "object" && ("err" in arg) && !("msg" in arg)) arg["msg"] = arg.msg = "An unknown error occurred";} catch {}
    try {if (typeof arg == "object" && ("cerr" in arg) && ("isCrossauthError" in arg.cerr) && arg.cerr ) {arg["errorCode"] = arg.cerr.code; arg["errorCodeName"] = arg.cerr.codeName; arg["httpStatus"] = arg.cerr.httpStatus; if (!("msg" in arg)) arg["msg"] = arg.cerr.message; delete arg.cerr;}} catch {}
    return (typeof arg == "string" || globalThis.crossauthLoggerAcceptsJson) ? arg : JSON.stringify(arg);
}

declare global {
    var crossauthLogger : CrossauthLoggerInterface;
    var crossauthLoggerAcceptsJson : boolean;
};

globalThis.crossauthLogger = new CrossauthLogger(CrossauthLogger.None);
globalThis.crossauthLoggerAcceptsJson = true;
