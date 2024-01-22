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
            const levelName = (process.env["CROSSAUTH_LOG_LEVEL"]||"ERROR").toUpperCase();
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
    return (typeof arg == "string" || globalThis.crossauthLoggerAcceptsJson) ? arg : JSON.stringify(arg);
}

declare global {
    var crossauthLogger : CrossauthLoggerInterface;
    var crossauthLoggerAcceptsJson : boolean;
};

globalThis.crossauthLogger = new CrossauthLogger(CrossauthLogger.None);
globalThis.crossauthLoggerAcceptsJson = true;
