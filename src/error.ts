/**
 * Indicates the type of error reported by {@link index!CrossauthError}
 */
export enum ErrorCode {

    /** Thrown when a given username does not exist, eg during login */
	UserNotExist,

    /** Thrown when a password does not match, eg during login */
    PasswordNotMatch,

    /** For endpoints provided by servers in this package, this is returned instead of 
      * UserNotExist or PasswordNotMatch, for security reasons */
    UsernameOrPasswordInvalid,

    /** Thrown on login attempt with a user account marked inactive */
    UserNotActive,

    /** Thrown on login attempt with a user account marked not having had the email address validated */
    EmailNotVerified,

    /** Thrown when a resource expecting authorization was access and authorization not provided or wrong */
    Unauthorized,

    /** Thrown when a session or API key was provided that is not in the key table */
    InvalidKey,

    /** Thrown when a session or API key has expired */
    Expired,

    /** Thrown when there is a connection error, eg to a database */
	Connection,

    /** Thrown when a hash, eg password, is not in the given format */
    InvalidHash,

    /** Thrown for an condition not convered above. */
    UnknownError,
}

/**
 * Thrown by Crossauth functions whenever it encounters an error.
 */
export class CrossauthError extends Error {

    readonly code : ErrorCode;

    /**
     * Creates a new error to throw,
     * 
     * @param code describes the type of error
     * @param message if provided, this error will display.  Otherwise a default one for the error code will be used.
     */
    constructor(code : ErrorCode, message : string | undefined = undefined) {
        let _message : string;
        if (message != undefined) {
            _message = message;
        } else {
            if (code == ErrorCode.UserNotExist) {
                _message = "Username does not exist";
            } else if (code == ErrorCode.PasswordNotMatch) {
                _message = "Password doesn't match"
            } else if (code == ErrorCode.UserNotActive) {
                _message = "Account is not active"
            } else if (code == ErrorCode.EmailNotVerified) {
                _message = "Email address has not been verified"
            } else if (code == ErrorCode.Unauthorized) {
                _message = "Not authorized"
            } else if (code == ErrorCode.Connection) {
                _message = "Connection failure";
            } else if (code == ErrorCode.Expired) {
                _message = "Token has expired";
            } else if (code == ErrorCode.InvalidHash) {
                _message = "Password hash is not in a valid format";
            } else if (code == ErrorCode.InvalidKey) {
                _message = "Key is not valid";
            } else {
                _message = "Unknown error";
            }    
        }
        super(_message); // 'Error' breaks prototype chain here
        this.code = code;
        this.name = 'CrossauthError';
        //Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
    }
}
