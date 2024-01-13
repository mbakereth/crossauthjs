/**
 * Indicates the type of error reported by {@link index!CrossauthError}
 */
export enum ErrorCode {

    /** Thrown when a given username does not exist, eg during login */
	UserNotExist,

    /** Thrown when a password does not match, eg during login or signup */
    PasswordNotMatch,

    /** Thrown when a a password reset is requested and the email does not exist */
    EmailNotExist,

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

    /** Thrown when an algorithm is requested but not supported, eg hashing algorithm */
    UnsupportedAlgorithm,

    /** Thrown if you try to create a key which already exists in key storage */
    KeyExists,

    /** Thrown if the user needs to reset his or her password */
    PasswordResetNeeded,

    /** Thrown when something is missing or inconsistent in configuration */
    Configuration,

    /** Thrown if an email address in invalid */
    InvalidEmail,

    /** Thrown when two passwords do not match each other (eg signup) */
    PasswordMatch,

    /** Thrown when a password does not match rules (length, uppercase/lowercase/digits) */
    PasswordFormat,

    /** Thrown when attempting to create a user that already exists */
    UserExists,

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
            } else if (code == ErrorCode.UsernameOrPasswordInvalid) {
                _message = "Username or password incorrect"
            } else if (code == ErrorCode.EmailNotExist) {
                _message = "No user exists with that email address"
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
                _message = "Hash is not in a valid format";
            } else if (code == ErrorCode.InvalidKey) {
                _message = "Key is not valid";
            } else if (code == ErrorCode.UnsupportedAlgorithm) {
                _message = "Algorithm not supported";
            } else if (code == ErrorCode.KeyExists) {
                _message = "Attempt to create a key that already exists";
            } else if (code == ErrorCode.PasswordResetNeeded) {
                _message = "User must reset password";
            } else if (code == ErrorCode.Configuration) {
                _message = "There was an error in the configuration";
            } else if (code == ErrorCode.PasswordMatch) {
                _message = "Passwords do not match";
            } else if (code == ErrorCode.PasswordFormat) {
                _message = "Password format was incorrect";
            } else if (code == ErrorCode.UserExists) {
                _message = "User already exists";
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
