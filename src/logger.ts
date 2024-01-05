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
    constructor(level: 0 | 1 | 2 | 3 | 4 = CrossauthLogger.Error) {
        this.level = level;
    }

    private log(level: 0 | 1 | 2 | 3 | 4 , output: any) {
        if (level <= this.level) {
            console.log("Crossauth " + CrossauthLogger.levelName[level] + " " + new Date().toISOString(), output);
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

    static setLogger(logger : CrossauthLoggerInterface) {
        globalThis.crossauthLogger = logger;
    }
}

declare global {
    var crossauthLogger : CrossauthLoggerInterface;
};

globalThis.crossauthLogger = new CrossauthLogger(CrossauthLogger.None);
