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

/**
 * A very simple logging class with no dependencies.
 * 
 * Logs to console. 
 */
class CrossauthLogger {

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
}

/**
 * Default Crossauth logger.  Change it to something else wiht {@link setCrossauthLogger}.
 * 
 * You can set the logger to anything that has the functions error(any), warn(any), 
 * info(any) and debug(any)
 */
export var crossauthLogger : any = new CrossauthLogger(CrossauthLogLevel.None);

export function setCrossauthLogger(newLogger : any) {
    crossauthLogger = newLogger;
}