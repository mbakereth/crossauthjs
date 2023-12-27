export enum ErrorCode {
	UserNotExist,
    PasswordNotMatch,
    Unauthorized,
    InvalidSessionId,
    Expired,
	Connection,
    InvalidHash,
    UnknownError,
}

export class CrossauthError extends Error {
    constructor(code : ErrorCode, message : string | undefined = undefined) {
        let _message : string;
        if (message != undefined) {
            _message = message;
        } else {
            if (code == ErrorCode.UserNotExist) {
                _message = "Username does not exist";
            } else if (code == ErrorCode.PasswordNotMatch) {
                _message = "Password doesn't match"
            } else if (code == ErrorCode.Unauthorized) {
                _message = "Not authorized"
            } else if (code == ErrorCode.Connection) {
                _message = "Connection failure";
            } else if (code == ErrorCode.Expired) {
                _message = "Token has expired";
            } else if (code == ErrorCode.InvalidHash) {
                _message = "Password hash is not in a valid format";
            } else if (code == ErrorCode.InvalidSessionId) {
                _message = "Session ID is not valid";
            } else {
                _message = "Unknown error";
            }    
        }
        super(_message); // 'Error' breaks prototype chain here
        this.name = 'CrossauthError';
        //Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
    }
}
