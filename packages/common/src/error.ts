// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
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

    /** This is returned if attempting to make a client which already exists (client_id or name/userid) */
    ClientExists,

    /** This is returned if an OAuth2 client secret is invalid */
    InvalidClientSecret,

    /** Server endpoints in this package will return this instead of InvalidClientId or InvalidClientSecret for security purposes */
    InvalidClientIdOrSecret,

    /** This is returned a request is made with a redirect Uri that is not registered */
    InvalidRedirectUri,

    /** This is returned a request is made with a an oauth flow name that is not recognized */
    InvalidOAuthFlow,

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

    /** Thrown for the OAuth insufficient_scope error  */
    InsufficientScope,

    /** Returned if user is valid but doesn't have permission to access resource */
    InsufficientPriviledges,

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
    PasswordChangeNeeded,

    /** Thrown if the user needs to reset his or her password */
    PasswordResetNeeded,

    /** Thrown if the user needs to reset factor2 before logging in */
    Factor2ResetNeeded,

    /** Thrown when something is missing or inconsistent in configuration */
    Configuration,

    /** Thrown if an email address in invalid */
    InvalidEmail,

    /** Thrown if a phone number in invalid */
    InvalidPhoneNumber,

    /** Thrown if an email address in invalid */
    InvalidUsername,

    /** Thrown when two passwords do not match each other (eg signup) */
    PasswordMatch,

    /** Thrown when a token (eg TOTP or OTP) is invalid */
    InvalidToken,

    /** Thrown during OAuth password flow if an MFA step is needed */
    MfaRequired,

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

    /** Thrown in the OAuth device code flow */
    AuthorizationPending,

    /** Thrown in the OAuth device code flow */
    SlowDown,

    /** Thrown in the OAuth device code flow */
    ExpiredToken,

    /** Thrown in database handlers where an insert causes a constraint violation */
    ConstraintViolation,

    /** Thrown if a method is unimplemented, typically when a feature
     * is not yet supported in this language. */
    NotImplemented,

    /** Thrown for an condition not convered above. */
    UnknownError,
}

/**
 * Thrown by Crossauth functions whenever it encounters an error.
 */
export class CrossauthError extends Error {

    /** `typeof` won't work on this class.  To determine if the 
     * object is a `CrossauthError`, check for presence of this member.
     */
    isCrossauthError = true;

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
            _message = "User does not exist";
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
        } else if (code == ErrorCode.ClientExists) {
            _message = "Client ID or name already exists"
            _httpStatus = 500;
        } else if (code == ErrorCode.InvalidClientSecret) {
            _message = "Client secret is invalid"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidClientIdOrSecret) {
            _message = "Client id or secret is invalid"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidRedirectUri) {
            _message = "Redirect Uri is not registered"
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidOAuthFlow) {
            _message = "Invalid OAuth flow type"
            _httpStatus = 500;
        } else if (code == ErrorCode.EmailNotExist) {
            _message = "No user exists with that email address"
            _httpStatus = 401;
        } else if (code == ErrorCode.UserNotActive) {
            _message = "Account is not active"
            _httpStatus = 403;
        } else if (code == ErrorCode.InvalidUsername) {
            _message = "Username is not in an allowed format"
            _httpStatus = 400;
        } else if (code == ErrorCode.InvalidEmail) {
            _message = "Email is not in an allowed format"
            _httpStatus = 400;
        } else if (code == ErrorCode.InvalidPhoneNumber) {
            _message = "Phone number is not in an allowed format"
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
            _httpStatus = 403;
        } else if (code == ErrorCode.InsufficientScope) {
            _message = "Insufficient scope"
            _httpStatus = 403;
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
        } else if (code == ErrorCode.Forbidden) {
            _message = "You do not have permission to access this resource";
            _httpStatus = 403;
        } else if (code == ErrorCode.InsufficientPriviledges) {
            _message = "You do not have the right privileges to access this resource";
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
        } else if (code == ErrorCode.PasswordChangeNeeded) {
            _message = "User must change password";
            _httpStatus = 403;
        } else if (code == ErrorCode.PasswordResetNeeded) {
            _message = "User must reset password";
            _httpStatus = 403;
        } else if (code == ErrorCode.Factor2ResetNeeded) {
            _message = "User must reset 2FA";
            _httpStatus = 403;
        } else if (code == ErrorCode.Configuration) {
            _message = "There was an error in the configuration";
        } else if (code == ErrorCode.PasswordMatch) {
            _message = "Passwords do not match";
            _httpStatus = 401;
        } else if (code == ErrorCode.InvalidToken) {
            _message = "Token is not valid";
            _httpStatus = 401;
        } else if (code == ErrorCode.MfaRequired) {
            _message = "MFA is required";
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
        } else if (code == ErrorCode.AuthorizationPending) {
            _message = "Waiting for authorization";
            _httpStatus = 200;
        } else if (code == ErrorCode.SlowDown) {
            _message = "Slow polling down by 5 seconds";
            _httpStatus = 200;
        } else if (code == ErrorCode.ExpiredToken) {
            _message = "Token has expired";
            _httpStatus = 401;
        } else if (code == ErrorCode.ConstraintViolation) {
            _message = "Database update/insert caused a constraint violation";
            _httpStatus = 500;
        } else if (code == ErrorCode.NotImplemented) {
            _message = "This method has not been implemented";
            _httpStatus = 500;
        } else {
            _message = "Unknown error";
            _httpStatus = 500;
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
	Object.setPrototypeOf(this, CrossauthError.prototype);
    }

    /**
     * OAuth defines certain error types.  To convert the error in an OAuth
     * response into a CrossauthError object, call this function.
     * 
     * @param error as returned by an OAuth call (converted to an {@link @crossauth/common!ErrorCode}).
     * @param error_description as returned by an OAuth call (put in the `message`)
     * @returns a `CrossauthError` instance.
     */
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
            case "invalid_token": code = ErrorCode.InvalidToken; break;
            case "expired_token": code = ErrorCode.ExpiredToken; break;
            case "insufficient_scope": code = ErrorCode.InvalidToken; break;
            case "mfa_required": code = ErrorCode.MfaRequired; break;
            case "authorization_pending": code = ErrorCode.AuthorizationPending; break;
            case "slow_down": code = ErrorCode.SlowDown; break;
            default: code = ErrorCode.UnknownError;
        }
        return new CrossauthError(code, error_description);
            
    }

    get oauthErrorCode() {
        switch (this.code) {
            case ErrorCode.BadRequest: return "invalid_request";
            case ErrorCode.UnauthorizedClient: return "unauthorized_client";
            case ErrorCode.Unauthorized: return  "access_denied";
            case ErrorCode.InvalidScope: return "invalid_scope";
            case ErrorCode.Connection: return "temporarily_unavailable";
            case ErrorCode.InvalidToken: return "invalid_token";
            case ErrorCode.MfaRequired: return "mfa_required";
            case ErrorCode.AuthorizationPending: return "authorization_pending";
            case ErrorCode.SlowDown: return "slow_down";
            case ErrorCode.ExpiredToken: return "expired_token";
            case ErrorCode.Expired: return "expired_token";
            default: return "server_error";
        }
    }

    /**
     * If the passed object is a `CrossauthError` instance, simply returns
     * it.  
     * If not and it is an object with `errorCode` in it, creates a 
     * CrossauthError from that and `errorMessage`, if present.
     * Otherwise creates a `CrossauthError` object with {@link @crossauth/common!ErrorCode}
     * of `Unknown` from it, setting the `message` if possible.
     * 
     * @param e the error to convert.
     * @returns  a `CrossauthError` instance.
     */
    static asCrossauthError(e: any, defaultMessage? : string) : CrossauthError { 
        if (e instanceof Error) {
            if ("isCrossauthError" in e) {
                return e as CrossauthError;
            } 
            return new CrossauthError(ErrorCode.UnknownError, e.message);
        } else if ("errorCode" in e) {
            let errorCode = ErrorCode.UnknownError;
            try {
                errorCode = Number(e["errorCode"]) ?? ErrorCode.UnknownError;
            } catch {}
            let errorMessage = defaultMessage ?? ErrorCode[errorCode];
            if ("errorMessage" in e) errorMessage = e["errorMessage"];
            else if ("message" in e) errorMessage = e["message"];
            return new CrossauthError(errorCode, errorMessage);
        }
        let errorMessage = defaultMessage ?? ErrorCode[ErrorCode.UnknownError];
        if ("message" in e) errorMessage = e["message"];
        return new CrossauthError(ErrorCode.UnknownError, errorMessage);
    }
}

/**
 * Returns the friendly name for an HTTP response code.  
 * 
 * If it is not a recognized one, returns the friendly name for 500.
 * @param status the HTTP response code, which, while being numeric,
 *        can be in a string or number.
 * @returns the string version of the response code.
 */
export function httpStatus(status: string|number) : string {
    if (typeof status == "number") status = ""+status;
    if (status in FriendlyHttpStatus) return FriendlyHttpStatus[status];
    return FriendlyHttpStatus['500'];
}

/**
 * Name for a numeric response code, as defined by the HTTP specification.
 */
const FriendlyHttpStatus : {[key:string]:string} = {
    '200': 'OK',
    '201': 'Created',
    '202': 'Accepted',
    '203': 'Non-Authoritative Information',
    '204': 'No Content',
    '205': 'Reset Content',
    '206': 'Partial Content',
    '300': 'Multiple Choices',
    '301': 'Moved Permanently',
    '302': 'Found',
    '303': 'See Other',
    '304': 'Not Modified',
    '305': 'Use Proxy',
    '306': 'Unused',
    '307': 'Temporary Redirect',
    '400': 'Bad Request',
    '401': 'Unauthorized',
    '402': 'Payment Required',
    '403': 'Forbidden',
    '404': 'Not Found',
    '405': 'Method Not Allowed',
    '406': 'Not Acceptable',
    '407': 'Proxy Authentication Required',
    '408': 'Request Timeout',
    '409': 'Conflict',
    '410': 'Gone',
    '411': 'Length Required',
    '412': 'Precondition Required',
    '413': 'Request Entry Too Large',
    '414': 'Request-URI Too Long',
    '415': 'Unsupported Media Type',
    '416': 'Requested Range Not Satisfiable',
    '417': 'Expectation Failed',
    '418': 'I\'m a teapot',
    '429': 'Too Many Requests',
    '500': 'Internal Server Error',
    '501': 'Not Implemented',
    '502': 'Bad Gateway',
    '503': 'Service Unavailable',
    '504': 'Gateway Timeout',
    '505': 'HTTP Version Not Supported',
};
