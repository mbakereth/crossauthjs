/**
 * Errors that can be returned from OAuth2 endpoints
 */
export enum OAuthErrorCode {
    /** Thrown when a given username does not exist, eg during login */
    invalid_request = 101,
    unauthorized_client = 102,
    access_denied = 103,
    unsupported_response_type = 104,
    invalid_scope = 105,
    server_error = 106,
    temporarily_unavailable = 107,
  };

/**
 * Indicates the type of error reported by {@link @crossauth/common!CrossauthError}
 */
export enum ErrorCode {

    /** Thrown when a given username does not exist, eg during login */
	UserNotExist = 0,

    /** Thrown when a password does not match, eg during login or signup */
    PasswordInvalid,

    /** Thrown when a a password reset is requested and the email does not exist */
    EmailNotExist,

    /** For endpoints provided by servers in this package, this is returned instead of 
      * UserNotExist or PasswordNotMatch, for security reasons */
    UsernameOrPasswordInvalid,

    /** This is returned if an OAuth2 client id is invalid */
    InvalidClientId,

    /** This is returned if an OAuth2 client secret is invalid */
    InvalidClientSecret,

    /** Server endpoints in this package will return this instead of InvalidClientId or InvalidClientSecret for security purposes */
    InvalidClientIdOrSecret,

    /** This is returned a request is made with a redirect Uri that is not registered */
    InvalidRedirectUri,

    /** Thrown on login attempt with a user account marked inactive */
    UserNotActive,

    /** Thrown on login attempt with a user account marked not having had the email address validated */
    EmailNotVerified,

    /** Thrown on login attempt with a user account marked not having completed 2FA setup */
    TwoFactorIncomplete,

    /** Thrown when a resource expecting user authorization was access and authorization not provided or wrong */
    Unauthorized,

    /** Thrown for the OAuth unauthorized_client error (when the client is unauthorized as opposed to the user) */
    UnauthorizedClient,

    /** Thrown for the OAuth invalid_scope error  */
    InvalidScope,

    /** Returned with an HTTP 403 response */
    Forbidden,

    /** Thrown when a session or API key was provided that is not in the key table.
     * For CSRF and sesison keys, an InvalidCsrf or InvalidSession will be thrown instead
     */
    InvalidKey,

    /** Thrown if the CSRF token is invalid
     */
    InvalidCsrf,

    /** Thrown if the session cookie is invalid
     */
    InvalidSession,

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

    /** Thrown if an email address in invalid */
    InvalidUserame,

    /** Thrown when two passwords do not match each other (eg signup) */
    PasswordMatch,

    /** Thrown when a token (eg TOTP or OTP) is invalid */
    InvalidToken,

    /** Thrown when a password does not match rules (length, uppercase/lowercase/digits) */
    PasswordFormat,

    /** Thrown when a the data field of key storage is not valid json */
    DataFormat,

    /** Thrown if a fetch failed */
    FetchError,

    /** Thrown when attempting to create a user that already exists */
    UserExists,

    /** Thrown by user-supplied validation functions if a user details form was incorrectly filled out */
    FormEntry,

    /** Thrown when an invalid request is made, eg configure 2FA when 2FA is switched off for user */
    BadRequest,

    /** Thrown for an condition not convered above. */
    UnknownError,

    // OAuthErrors 

    /** OAuth invalid_request - See RFC 6749 */
    invalid_request = 101,

    /** OAuth unauthorized_client - See RFC 6749 */
    unauthorized_client = 102,

    /** OAuth access_denied - See RFC 6749 */
    access_denied = 103,

    /** OAuth unsupported_response_type - See RFC 6749 */
    unsupported_response_type = 104,

    /** OAuth invalid_scope - See RFC 6749 */
    invalid_scope = 105,

    /** OAuth server_error - See RFC 6749 */
    server_error = 106,

    /** OAuth temporarily_unavailable - See RFC 6749 */
    temporarily_unavailable = 107,
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
        if (code == ErrorCode.UserNotExist) {
            _message = "Username does not exist";
            _httpStatus = 401;
        } else if (code == ErrorCode.PasswordInvalid) {
            _message = "Password doesn't match"
            _httpStatus = 401;
        } else if (code == ErrorCode.UsernameOrPasswordInvalid) {
            _message = "Username or password incorrect"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidClientId) {
            _message = "Client id is invalid"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidClientSecret) {
            _message = "Client secret is invalid"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidClientIdOrSecret) {
            _message = "Client id or secret is invalid"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidRedirectUri) {
            _message = "Redirect Uri is not registered"
            _httpStatus = 401;
        } else if (code == ErrorCode.EmailNotExist) {
            _message = "No user exists with that email address"
            _httpStatus = 401;
        } else if (code == ErrorCode.UserNotActive) {
            _message = "Account is not active"
            _httpStatus = 403;
        } else if (code == ErrorCode.InvalidUserame) {
            _message = "Username is not in an allowed format"
            _httpStatus = 400;
        } else if (code == ErrorCode.InvalidEmail) {
            _message = "Email is not in an allowed format"
            _httpStatus = 400;
        } else if (code == ErrorCode.EmailNotVerified) {
            _message = "Email address has not been verified"
            _httpStatus = 403;
        } else if (code == ErrorCode.TwoFactorIncomplete) {
            _message = "Two-factor setup is not complete"
            _httpStatus = 403;
        } else if (code == ErrorCode.Unauthorized) {
            _message = "Not authorized"
            _httpStatus = 401;
        } else if (code == ErrorCode.UnauthorizedClient) {
            _message = "Client not authorized"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidScope) {
            _message = "Invalid scope"
            _httpStatus = 402;
        } else if (code == ErrorCode.Connection) {
            _message = "Connection failure";
        } else if (code == ErrorCode.Expired) {
            _message = "Token has expired";
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidHash) {
            _message = "Hash is not in a valid format";
        } else if (code == ErrorCode.InvalidKey) {
            _message = "Key is invalid";
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidCsrf) {
            _message = "CSRF token is invalid";
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidSession) {
            _message = "Session cookie is invalid";
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
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidToken) {
            _message = "Token is not valid";
            _httpStatus = 401;
        } else if (code == ErrorCode.PasswordFormat) {
            _message = "Password format was incorrect";
            _httpStatus = 401;
        } else if (code == ErrorCode.UserExists) {
            _message = "User already exists";
            _httpStatus = 400;
        } else if (code == ErrorCode.BadRequest) {
            _message = "The request is invalid";
            _httpStatus = 400;
        } else if (code == ErrorCode.DataFormat) {
            _message = "Session data has unexpected format";
            _httpStatus = 500;
        } else if (code == ErrorCode.FetchError) {
            _message = "Couldn't execute a fetch";
            _httpStatus = 500;
        } else if (code == ErrorCode.invalid_request) {
            _message = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.";
            _httpStatus = 400;
        } else if (code == ErrorCode.unauthorized_client) {
            _message = "The client is not authorized to request an authorization code using this method.";
            _httpStatus = 401;
        } else if (code == ErrorCode.access_denied) {
            _message = "The resource owner or authorization server denied the request";
            _httpStatus = 401;
        } else if (code == ErrorCode.unsupported_response_type) {
            _message = "The authorization server does not support obtaining an authorization code using this method";
            _httpStatus = 400;
        } else if (code == ErrorCode.invalid_scope) {
            _message = "The requested scope is invalid, unknown, or malformed";
            _httpStatus = 401;
        } else if (code == ErrorCode.server_error) {
            _message = "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.";
            _httpStatus = 500;
        } else {
            _message = "Unknown error";
        }    
        if (message != undefined && !Array.isArray(message)) {
            _message = message;
        } else if (Array.isArray(message)) {
            _message = message.join(". ");
        }
        super(_message); 
        this.code = code;
        this.codeName = ErrorCode[code];
        this.httpStatus = _httpStatus;
        this.name = 'CrossauthError';
        if (Array.isArray(message)) this.messages = message;
        else this.messages = [_message];
    }

    static fromOAuthError(error : string, error_description?: string) : CrossauthError {
        let code : ErrorCode;
        switch (error) {
            case "invalid_request": code = ErrorCode.BadRequest; break
            case "unauthorized_client": code = ErrorCode.UnauthorizedClient; break;
            case "access_denied": code = ErrorCode.Unauthorized; break;
            case "unsupported_response_type": code = ErrorCode.BadRequest; break;
            case "invalid_scope": code = ErrorCode.InvalidScope; break;
            case "server_error": code = ErrorCode.UnknownError; break;
            case "temporarily_unavailable": code = ErrorCode.Connection; break;
            default: code = ErrorCode.server_error;
        }
        return new CrossauthError(code, error_description);
            
    }

    get oauthCode() : OAuthErrorCode {
        try {
            return OAuthErrorCode[ErrorCode[this.code] as keyof typeof OAuthErrorCode];
        } catch (e) {
        return OAuthErrorCode.server_error;
        }
    }
}

export function oauthErrorStatus(status : string) {
    switch (status) {
        case "invalid_request": return 400;
        case "unauthorized_client": return 401;
        case "access_denied": return 401;
        case "unsupported_response_type": return 400;
        case "invalid_scope": return 401;
        //case "server_error": 500;
        //case "temporarily_unavailable": return 500;
    }
    return 500;
};

export function errorCodeFromAuthErrorString(status : string) {
    switch (status) {
        case "invalid_request": return ErrorCode.invalid_request;
        case "unauthorized_client": return ErrorCode.unauthorized_client;
        case "access_denied": return ErrorCode.access_denied;
        case "unsupported_response_type": return ErrorCode.unsupported_response_type;
        case "invalid_scope": return ErrorCode.invalid_scope;
        case "server_error": return ErrorCode.server_error;
        case "temporarily_unavailable": return ErrorCode.temporarily_unavailable;
    }
    return ErrorCode.server_error;
};
