/**
 * Indicates the type of error reported by {@link index!CrossauthError}
 */
export enum ErrorCode {

    /** Thrown when a given username does not exist, eg during login */
	UserNotExist,

    /** Thrown when a password does not match, eg during login or signup */
    PasswordInvalid,

    /** Thrown when a a password reset is requested and the email does not exist */
    EmailNotExist,

    /** For endpoints provided by servers in this package, this is returned instead of 
      * UserNotExist or PasswordNotMatch, for security reasons */
    UsernameOrPasswordInvalid,

    /** Thrown on login attempt with a user account marked inactive */
    UserNotActive,

    /** Thrown on login attempt with a user account marked not having had the email address validated */
    EmailNotVerified,

    /** Thrown on login attempt with a user account marked not having completed 2FA setup */
    TwoFactorIncomplete,

    /** Thrown when a resource expecting authorization was access and authorization not provided or wrong */
    Unauthorized,

    /** Returned with an HTTP 403 response */
    Forbidden,

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

    /** Thrown when a the data field of key storage is not valid json */
    DataFormat,

    /** Thrown when attempting to create a user that already exists */
    UserExists,

    /** Thrown by user-supplied validation functions if a user details form was incorrectly filled out */
    FormEntry,

    /** Thrown when an invalid request is made, eg configure 2FA when 2FA is switched off for user */
    BadRequest,

    /** Thrown for an condition not convered above. */
    UnknownError,
}

/**
 * Thrown by Crossauth functions whenever it encounters an error.
 */
export class CrossauthError extends Error {

    /** The best HTTP status to report */
    readonly httpStatus: number;

    /** All Crossauth errors have an error code */
    readonly code : ErrorCode;

    /** All Crossauth errors have an error code */
    readonly codeName : string;

    /** A vector of error messages.  If there was only one, it will still be in this array.
     * The inherited property `message` is also always available.  If there were multiple messages,
     * it will be a concatenation of them with `". "` in between.
     */
    readonly messages : string[];

    /**
     * Creates a new error to throw,
     * 
     * @param code describes the type of error
     * @param message if provided, this error will display.  Otherwise a default one for the error code will be used.
     */
    constructor(code : ErrorCode, message : string | string[] | undefined = undefined) {
        let _message : string;
        let _httpStatus = 500;
        if (message != undefined && !Array.isArray(message)) {
            _message = message;
        } else if (Array.isArray(message)) {
            _message = message.join(". ");
        } else {
            if (code == ErrorCode.UserNotExist) {
                _message = "Username does not exist";
                _httpStatus = 401;
            } else if (code == ErrorCode.PasswordInvalid) {
                _message = "Password doesn't match"
                _httpStatus = 401;
            } else if (code == ErrorCode.UsernameOrPasswordInvalid) {
                _message = "Username or password incorrect"
                _httpStatus = 401;
            } else if (code == ErrorCode.EmailNotExist) {
                _message = "No user exists with that email address"
                _httpStatus = 401;
            } else if (code == ErrorCode.UserNotActive) {
                _message = "Account is not active"
                _httpStatus = 403;
            } else if (code == ErrorCode.EmailNotVerified) {
                _message = "Email address has not been verified"
                _httpStatus = 403;
            } else if (code == ErrorCode.TwoFactorIncomplete) {
                _message = "TOTP setup is not complete"
                _httpStatus = 403;
            } else if (code == ErrorCode.Unauthorized) {
                _message = "Not authorized"
                _httpStatus = 401;
            } else if (code == ErrorCode.Connection) {
                _message = "Connection failure";
            } else if (code == ErrorCode.Expired) {
                _message = "Token has expired";
                _httpStatus = 401;
            } else if (code == ErrorCode.InvalidHash) {
                _message = "Hash is not in a valid format";
            } else if (code == ErrorCode.InvalidKey) {
                _message = "Key is not valid";
                _httpStatus = 401;
            } else if (code == ErrorCode.UnsupportedAlgorithm) {
                _message = "Algorithm not supported";
            } else if (code == ErrorCode.KeyExists) {
                _message = "Attempt to create a key that already exists";
            } else if (code == ErrorCode.PasswordResetNeeded) {
                _message = "User must reset password";
                _httpStatus = 403;
            } else if (code == ErrorCode.Configuration) {
                _message = "There was an error in the configuration";
            } else if (code == ErrorCode.PasswordMatch) {
                _message = "Passwords do not match";
                _httpStatus = 400;
            } else if (code == ErrorCode.PasswordFormat) {
                _message = "Password format was incorrect";
                _httpStatus = 400;
            } else if (code == ErrorCode.UserExists) {
                _message = "User already exists";
                _httpStatus = 400;
            } else if (code == ErrorCode.BadRequest) {
                _message = "The request is invalid";
                _httpStatus = 400;
            } else if (code == ErrorCode.DataFormat) {
                _message = "Session data has unexpected format";
                _httpStatus = 500;
            } else {
                _message = "Unknown error";
            }    
        }
        super(_message); 
        this.code = code;
        this.codeName = ErrorCode[code];
        this.httpStatus = _httpStatus;
        this.name = 'CrossauthError';
        if (Array.isArray(message)) this.messages = message;
        else this.messages = [_message];
    }

}
