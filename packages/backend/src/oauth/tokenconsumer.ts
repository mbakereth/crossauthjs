import { KeyStorage } from '../storage';
import { setParameter, ParamType } from '../utils';
import { Crypto } from '../crypto';
import { CrossauthLogger, j } from '@crossauth/common';
import { CrossauthError, ErrorCode, KeyPrefix } from '@crossauth/common';
import fs from 'node:fs';
import {
    OAuthTokenConsumerBase,
    type OAuthTokenConsumerBaseOptions } from '@crossauth/common';

/**
 * Options for {@link OAuthTokenConsumer}
 */
export interface OAuthTokenConsumerOptions 
    extends OAuthTokenConsumerBaseOptions {

    /** Whether to persist access tokens in key storage.  Default false.
     * 
     * If you set this to true, you must also set `keyStorage`.
     */
    persistAccessToken? : boolean,

    /** If persisting tokens, you need to provide a storage to persist them to */
    keyStorage? : KeyStorage,

    /** Filename with secret key if using a symmetric cipher for signing the 
     * JWT.  Either this or `jwtSecretKey` is required when using this kind 
     * of cipher */
    jwtSecretKeyFile? : string,

    /** Filename for the public key if using a public key cipher for signing the 
     * JWT.  Either this or `jwtPublicKey` is required when using this kind of 
     * cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKeyFile? : string,

    /**
     * The aud claim needs to match this value.
     * No default (required)
     */
    audience? : string,
}

/**
 * This class validates access tokens.
 * 
 * It is separated into its own class as the functionality is used in both
 * the OAuth resource server and OAuth client
 */
export class OAuthTokenConsumer extends OAuthTokenConsumerBase {
    
    /**
     * Value passed to the constructor.  The `aud` claim must match it
     */
    protected readonly audience : string;

    /**
     * Value passed to the constructor. If true, access tokens are saved
     * in storage,
     */
    protected readonly persistAccessToken = false;

    private keyStorage? : KeyStorage;
    private jwtSecretKeyFile = "";
    private jwtPublicKeyFile = "";

    /**
     * Constructor
     * 
     * @param options see {@link OAuthTokenConsumerOptions}
     */
    constructor(options : OAuthTokenConsumerOptions = {}) {

        const options1 : {
            jwtKeyType? : string,
            audience : string,
        } = {audience: ""};
        setParameter("jwtKeyType", ParamType.String, options1, options, "JWT_KEY_TYPE");
        setParameter("audience", ParamType.String, options1, options, "OAUTH_AUDIENCE", true);
        super(options1.audience, {...options, ...options1});
        this.audience = options1.audience;

        setParameter("authServerBaseUrl", ParamType.String, this, options, "AUTH_SERVER_BASE_URL", true);
        setParameter("jwtSecretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("jwtPublicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("jwtSecretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("jwtPublicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("persistAccessToken", ParamType.Boolean, this, options, "OAUTH_PERSIST_ACCESS_TOKEN");

        this.keyStorage = options.keyStorage;

        if (this.jwtSecretKey || this.jwtSecretKeyFile) {
            if (this.jwtPublicKey || this.jwtPublicKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric and public/private JWT keys")
            }
            if (this.jwtSecretKey && this.jwtSecretKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric key and file")
            }
            if (this.jwtSecretKeyFile) {
                this.jwtSecretKey = 
                    fs.readFileSync(this.jwtSecretKeyFile, 'utf8');
            }
        } else if ((this.jwtPublicKey || this.jwtPublicKeyFile)) {
            if (this.jwtPublicKeyFile && this.jwtPublicKey) {
                throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify both public key and public key file");
            }
            if (this.jwtPublicKeyFile) {
                this.jwtPublicKey = 
                    fs.readFileSync(this.jwtPublicKeyFile, 'utf8');
            }
        } /*else {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Must specify either a JWT secret key or a public key");
        }*/
    }

    /**
     * Uses {@link Crypto.hash} to hash the given string.
     * 
     * @param plaintext the string to hash
     * @returns Base64-url-encoded hash
     */
    hash(plaintext : string) : string { 
        return Crypto.hash(plaintext); 
    }

    /**
     * If the given token is valid, the paylaod is returned.  Otherwise
     * undefined is returned.  
     * 
     * The signature must be valid, the expiry must not have passed and,
     * if `tokenType` is defined,. the `type` claim in the payload must
     * match it.
     * 
     * Doesn't throw exceptions.
     * 
     * @param token The token to validate
     * @param tokenType If defined, the `type` claim in the payload must
     *        match this value
     * @returns 
     */
    async tokenAuthorized(token: string,
        tokenType: "access" | "refresh" | "id") : 
        Promise<{[key:string]: any}|undefined> {
        const payload = await super.tokenAuthorized(token, tokenType);
        if (payload) {
            if (tokenType == "access" && this.persistAccessToken && 
                this.keyStorage) {
                try {
                    const key = KeyPrefix.accessToken + Crypto.hash(payload.jti);
                    const tokenInStorage = await this.keyStorage.getKey(key);
                    const now = new Date();
                    if (tokenInStorage.expires && 
                        tokenInStorage.expires?.getTime() < now.getTime()) {
                        CrossauthLogger.logger.error("Access token expired in storage but not in JWT");
                        return undefined;
                    }
                } catch (e) {
                    CrossauthLogger.logger.warn(j({msg: "Couldn't get token from database - is it valid?", 
                        hashedAccessToken: Crypto.hash(payload.jti)}))
                    CrossauthLogger.logger.debug(j({err: e}));
                    return undefined;
                }
            }
        }
        return payload;
    }
};
