/**
 * The log level for {@link CrossauthLogger}
 */
export enum CrossauthLogLevel {
    None = 0,
    Error,
    Warn,
    Info,
    Debug
  }

export interface CrossauthLoggerInterface {
    error(output: any) : void;
    warn(output: any) : void;
    info(output: any) : void;
    debug(output: any) : void;
}
/**
 * 
 * A very simple logging class with no dependencies.
 * 
 * Logs to console. 
 */
export class CrossauthLogger {

    private static instance : CrossauthLoggerInterface;

    /**
     * Return the singleton instance of the logger.
     * @returns the logger
     */
    static getInstance() : CrossauthLoggerInterface { 
        if (!CrossauthLogger.instance) {
            CrossauthLogger.instance = new CrossauthLogger(CrossauthLogLevel.Debug);
        }
        return CrossauthLogger.instance;
    }

    /** the log level. This can be set dynamically */
    level : CrossauthLogLevel;
    static levelName = ["NONE", "ERRRO", "WARN", "INFO", "DEBUG"];

    /**
     * Create a logger with the given level
     * @param level the level to report to
     */
    constructor(level: CrossauthLogLevel = CrossauthLogLevel.Error) {
        this.level = level;
    }

    private log(level: CrossauthLogLevel, output: any) {
        if (level <= this.level) {
            console.log("Crossauth " + CrossauthLogger.levelName[level] + " " + new Date().toISOString(), output);
        }
    }

    /**
     * Report an error
     * @param output object to output
     */
    error(output: any) {
        this.log(CrossauthLogLevel.Error, output);
    }

    warn(output: any) {
        this.log(CrossauthLogLevel.Warn, output);
    }

    info(output: any) {
        this.log(CrossauthLogLevel.Info, output);
    }

    debug(output: any) {
        this.log(CrossauthLogLevel.Debug, output);
    }

    setCrossauthLogger(logger : CrossauthLoggerInterface) {
        CrossauthLogger.instance = logger;
    }
}
