import { OAuthClientBase, OAuthFlows } from '@crossauth/common';
import { Crypto } from '../crypto';
import { setParameter, ParamType } from '../utils';
import { CrossauthError, ErrorCode  } from '@crossauth/common';
import {
    OAuthTokenConsumer,
    type OAuthTokenConsumerOptions } from './tokenconsumer';

/**
 * Options for {@link OAuthClientBackend}
 */
export interface OAuthClientOptions extends OAuthTokenConsumerOptions {

    /** Length of random state variable for passing to `authorize` endpoint
     * (before bsae64-url-encoding)
     */
    stateLength? : number,

    /** Length of random code verifier to generate 
     * (before bsae64-url-encoding) 
     * */
    verifierLength? : number,

    /**
     * Client ID for this client
     */
    clientId? : string,

    /**
     * Client secret for this client (can be undefined for no secret)
     */
    clientSecret? : string,

    /**
     * Redirect URI to send in `authorize` requests
     */
    redirectUri? : string,

    /**
     * Type of code challenge for PKCE
     */
    codeChallengeMethod? : "plain" | "S256"

    /**
     * Set of flows to enable (see {@link @crossauth/common!OAuthFlows})
     */
    validFlows? : string[],
}

/**
 * An OAuth clientframework-independent base class)
 * 
 * Most of the functionality is in the base class 
 * {@link @crossauth/common!OAuthClientBase}.  However that class is designed
 * to work in the browser as well as node, and therefore the cryptography
 * is let out of there and added in here.
 */
export class OAuthClientBackend extends OAuthClientBase {
    protected validFlows : string[] = [];

    /**
     * Constructor
     * @param jwtIssuer bsae URI for the authorization server
     *        expected to issue access tokens.  If the `iss` field in a JWT
     *        does not match this, it is rejected.
     * @param options See {@link OAuthClientOptions}
     */
    constructor(jwtIssuer : string, options : OAuthClientOptions) {
        // because we can't set instance variables before calling super()
        const options1 = {
            clientId: "",
        }
        setParameter("clientId", ParamType.String, options1, options, "OAUTH_CLIENT_ID", true);
        super({ jwtIssuer, 
            tokenConsumer: new OAuthTokenConsumer({ 
                audience: options1.clientId, 
                jwtIssuer, 
                ...options }), ...options });

        setParameter("stateLength", ParamType.String, this, options, "OAUTH_STATE_LENGTH");
        setParameter("verifierLength", ParamType.String, this, options, "OAUTH_VERIFIER_LENGTH");
        setParameter("clientId", ParamType.String, this, options, "OAUTH_CLIENT_ID");
        setParameter("clientSecret", ParamType.String, this, options, "OAUTH_CLIENT_SECRET");
        setParameter("codeChallengeMethod", ParamType.String, this, options, "OAUTH_CODE_CHALLENGE_METHOD");
        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_VALID_FLOWS");
        if (this.validFlows.length == 1 && this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        } else {
            if (!OAuthFlows.areAllValidFlows(this.validFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.validFlows.join(","));
            }
        }
    }

    /**
     * Uses {@link @crossauth/backend!Crypto.randomValue} to create a random string
     * @param length the length of the random array of bytes before
     *        base64-url-encoding
     * @returns the Base64-URL-encoded random string
     */
    protected randomValue(length : number) : string {
        return Crypto.randomValue(length);
    }

    /**
     * Uses {@link @crossauth/backend!Crypto.sha256} to create hash a string using SHA256
     * @param plaintext the text to hash
     * @returns the Base64-URL-encoded hash
     */
    protected sha256(plaintext :string) : string {
        return Crypto.sha256(plaintext);
    }
}
