import { CrossauthError, ErrorCode } from ".";
import { CrossauthLogger, j } from '.';

/**
 * Encapsulates the payload of a JWT, with both the token and
 * decoded JSON payload.
 */
export class JWT {

    /** The string representation of the JWT */
    token : string|undefined;

    /** The decoded payload from the token */
    payload : {[key:string]: any};

    /**
     * Constructor.  Pass either `token` or `payload`.
     * @param token the string JWT token - the payload will be parsed from it
     * @param payload the JSON payload.  The payload will be set but not
     *        the string `token`.
     */
    constructor({token, payload} : {
        token? : string,
        payload? : {[key:string]: any},
    }) {
        
        if (token) this.token = token;
        if (payload) {
            this.payload = payload;
        } else if (this.token) {
            const parts = this.token.split(".");
            if (parts.length != 3) throw new CrossauthError(ErrorCode.InvalidToken, "JWT not in correct format");
            try {
                this.payload = JSON.parse(parts[1]);
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                if (parts.length != 3) throw new CrossauthError(ErrorCode.InvalidToken, "JWT payload not in correct format");
                    const jsonString = Buffer.from(parts[1]).toString('base64url');
                    this.payload = JSON.parse(jsonString);
            }
        } else {
            this.payload = {};
        }
    }
}