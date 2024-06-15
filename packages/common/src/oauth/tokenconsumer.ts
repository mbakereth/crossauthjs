import * as jose from 'jose'
import { CrossauthLogger, j } from '../logger';
import { CrossauthError, ErrorCode } from '../error';
//import { createPublicKey, type JsonWebKey, KeyObject } from 'crypto'
import { type OpenIdConfiguration, DEFAULT_OIDCCONFIG } from './wellknown';

/** Allows passing either a Jose KeyLike object or a key as a binary array */
export type EncryptionKey = jose.KeyLike | Uint8Array;

/**
 * Options that can be passed to {@link OAuthTokenConsumerBase}.
 */
export interface OAuthTokenConsumerBaseOptions {

    /** Secret key if using a symmetric cipher for signing the JWT.  
     * Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtKeyType? : string,

    /** Secret key if using a symmetric cipher for signing the JWT.  
     * Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtSecretKey? : string,

    /** The public key if using a public key cipher for signing the JWT.  
     * Either this or `jwtPublicKeyFile` is required when using this kind of 
     * cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKey? : string,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** The value to expect in the iss
     * claim.  If the iss does not match this, the token is rejected.
     * No default (required) */
    authServerBaseUrl? : string;

    /**
     * For initializing the token consumer with a static OpenID Connect 
     * configuration.
     */
    oidcConfig? : (OpenIdConfiguration&{[key:string]:any})|undefined;

}

/**
 * This abstract class is for validating OAuth JWTs.  
 */
export abstract class OAuthTokenConsumerBase {
    
    protected audience : string;
    protected jwtKeyType  : string | undefined;
    protected jwtSecretKey : string | undefined;
    protected jwtPublicKey  : string | undefined;
    protected clockTolerance : number = 10;
    readonly authServerBaseUrl : string = "";

    /**
     * The OpenID Connect configuration for the authorization server,
     * either passed to the constructor or fetched from the authorization
     * server.
     */
    oidcConfig : (OpenIdConfiguration&{[key:string]:any})|undefined;

    /**
     * The RSA public keys or symmetric keys for the authorization server,
     * either passed to the constructor or fetched from the authorization
     * server.
     */
    keys : {[key:string]: EncryptionKey} = {};

    /**
     * Constrctor
     * 
     * @param audience : this is the value expected in the `aud` field
     *        of the JWT.  The token is rejected if it doesn't match.
     * @param options See {@link OAuthTokenConsumerBaseOptions}.
     */
    constructor(audience : string, options : OAuthTokenConsumerBaseOptions = {}) {

        this.audience = audience;

        if (options.authServerBaseUrl) this.authServerBaseUrl = options.authServerBaseUrl;
        if (options.jwtKeyType) this.jwtKeyType = options.jwtKeyType;
        if (options.jwtSecretKey) this.jwtSecretKey = options.jwtSecretKey;
        if (options.jwtPublicKey) this.jwtPublicKey = options.jwtPublicKey;
        if (options.clockTolerance) this.clockTolerance = options.clockTolerance;
        if (options.oidcConfig) this.oidcConfig = options.oidcConfig;

        if (this.jwtPublicKey && !this.jwtKeyType) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "If specifying jwtPublic key, must also specify jwtKeyType")
        }
    }

    /**
     * This loads keys either from the ones passed in the constructor
     * or by fetching from the authorization server.
     * 
     * Note that even if you pass the keys to the constructor, you must
     * still call this function.  This is because key loading is
     * asynchronous, and constructors may not be async.
     */
    async loadKeys() {

        try {
            if (this.jwtSecretKey) {
                if (!this.jwtKeyType) {
                    throw new CrossauthError(ErrorCode.Configuration,
                        "Must specify jwtKeyType if setting jwtSecretKey");
                }
                this.keys["_default"]
                    = await jose.importPKCS8(this.jwtSecretKey, this.jwtKeyType);
            } else if (this.jwtPublicKey) {
                if (!this.jwtKeyType) {
                    throw new CrossauthError(ErrorCode.Configuration,
                        "Must specify jwtKeyType if setting jwtPublicKey");
                }
                const key = await jose.importSPKI(this.jwtPublicKey, this.jwtKeyType);
                this.keys["_default"] = key;
                    
            } else {
                if (!this.oidcConfig) {
                    await this.loadConfig();
                }
                if (!this.oidcConfig) {
                    throw new CrossauthError(ErrorCode.Connection, 
                        "Load OIDC config before Jwks")
                }
                await this.loadJwks();
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Couldn't load keys");
        }
    }

    /**
     * Loads OpenID Connect configuration, or fetches it from the 
     * authorization server (using the well-known enpoint appended
     * to `authServerBaseUrl` )
     * @param oidcConfig the configuration, or undefined to load it from
     *        the authorization server
     * @throws a {@link @crossauth/common!CrossauthError} object with {@link @crossauth/common!ErrorCode} of
     *   - `Connection` if the fetch to the authorization server failed.
     */
    async loadConfig(oidcConfig? : OpenIdConfiguration) : Promise<void> {
        if (oidcConfig) {
            this.oidcConfig = oidcConfig;
            return;
        }

        if (!this.authServerBaseUrl) {
            throw new CrossauthError(ErrorCode.Connection, "Couldn't get OIDC configuration.  Either set authServerBaseUrl or set config manually");
        }
        let resp : Response|undefined = undefined;
        try {
            resp = await fetch(new URL("/.well-known/openid-configuration", this.authServerBaseUrl));
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
        }
        if (!resp || !resp.ok) {
            throw new CrossauthError(ErrorCode.Connection, "Couldn't get OIDC configuration");
        }
        this.oidcConfig = {...DEFAULT_OIDCCONFIG};

        // fetch config
        try {
            const body = await resp.json();
            for (const [key, value] of Object.entries(body)) {
                this.oidcConfig[key] = value;
            }
        } catch (e) {
            throw new CrossauthError(ErrorCode.Connection, "Unrecognized response from OIDC configuration endpoint");
        }
        
    }

    /**
     * Loads the JWT signature validation keys, or fetches them from the 
     * authorization server (using the URL in the OIDC configuration).
     * @param jwks the keys to load, or undefined to fetch them from
     *        the authorization server.
     * @throws a {@link @crossauth/common!CrossauthError} object with {@link @crossauth/common!ErrorCode} of
     *   - `Connection` if the fetch to the authorization server failed,
     *     the OIDC configuration wasn't set or the keys could not be parsed.
     */
    async loadJwks(jwks? : {keys: jose.JWK[]}) {
        if (jwks) {
            this.keys = {};
            for (let i=0; i<jwks.keys.length; ++i) {
                const key = jwks.keys[i];
                this.keys[key.kid??"_default"] = await jose.importJWK(jwks.keys[i]);
            }
        } else {
            if (!this.oidcConfig) {
                throw new CrossauthError(ErrorCode.Connection, "Load OIDC config before Jwks")
            }
            let resp : Response|undefined = undefined;
            try {
                resp = await fetch(new URL(this.oidcConfig.jwks_uri));
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
            }
            if (!resp || !resp.ok) {
                throw new CrossauthError(ErrorCode.Connection, "Couldn't get OIDC configuration");
            }
            this.keys = {};
            try {
                const body = await resp.json();
                if (!("keys" in body) || !Array.isArray(body.keys)) {
                    throw new CrossauthError(ErrorCode.Connection, "Couldn't fetch keys")
                }
                for (let i=0; i<body.keys.length; ++i) {
                    try {
                        let kid : string = "_default";
                        if ("kid" in body.keys[i] && typeof (body.keys[i]) == "string") kid = String(body.keys[i]);
                        const key =  await jose.importJWK(body.keys[i]);
                        this.keys[kid] = key;
                    } catch (e) {
                        CrossauthLogger.logger.error(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Couldn't load keys");
                    }
                }
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Unrecognized response from OIDC jwks endpoint");
            }
        }

    }

    /**
     * Returns JWT payload if the token is valid, undefined otherwise.
     * 
     * Doesn't throw exceptions.
     * 
     * @param token the token to validate
     * @param tokenType either `access`, `refresh` or `id`.  If the
     *        `type` field in the JWT payload doesn't match this, validation
     *        fails.
     * @returns the JWT payload if the token is valid, `undefined` otherwise.
     */
    async tokenAuthorized(token: string,
        tokenType: "access" | "refresh" | "id") : Promise<{[key:string]: any}|undefined> {
        if (!this.keys || Object.keys(this.keys).length == 0) {
            await this.loadKeys();
        }
        const decoded = await this.validateToken(token);
        if (!decoded) return undefined;
        if (decoded.type != tokenType) {
            CrossauthLogger.logger.error(j({msg: tokenType + " expected but got " + decoded.type}));
        }
        if (decoded.iss != this.authServerBaseUrl) {
            CrossauthLogger.logger.error(j({msg: `Invalid issuer ${decoded.iss} in access token`, hashedAccessToken: await this.hash(decoded.jti)}));
            return undefined;
        }
        if (decoded.aud) {
            if ((Array.isArray(decoded.aud) && !decoded.aud.includes(this.audience)) ||
                (!Array.isArray(decoded.aud) && decoded.aud != this.audience)) {
                    CrossauthLogger.logger.error(j({msg: `Invalid audience ${decoded.aud} in access token`, hashedAccessToken: await this.hash(decoded.jti)}));
                    return undefined;    
                }
        }
        return decoded;
    }

    private async validateToken(accessToken : string) : Promise<{[key:string]: any}|undefined> {

        // get KID from header
        if  (!this.keys || Object.keys(this.keys).length == 0) CrossauthLogger.logger.warn("No keys loaded so cannot validate tokens");
        let kid : string|undefined = undefined;
        try {
            const header = jose.decodeProtectedHeader(accessToken);
            kid = header.kid;
        } catch {
            CrossauthLogger.logger.warn(j({msg: "Invalid access token format"}))
            return undefined;
        }
        // find key matching header KID and validate signature (and expiry)
        let key : EncryptionKey|undefined = undefined;
        if ("_default" in this.keys) key = this.keys["_default"];
        for (let loadedKid in this.keys) {
            if (kid == loadedKid) {
                key = this.keys[loadedKid];
                break;
            }
        }
        if (!key) {
            CrossauthLogger.logger.warn(j({msg: "No matching keys found for access token"}));
            return undefined;
        }
        try {
            const { payload } = await jose.compactVerify(accessToken, key);
            const decodedPayload = JSON.parse(new TextDecoder().decode(payload));
            if (decodedPayload.exp*1000 < Date.now()+this.clockTolerance) {
                CrossauthLogger.logger.warn(j({msg: "Access token has expired"}));
                return undefined;     
            }
            return decodedPayload;
        } catch (e) {
            CrossauthLogger.logger.warn(j({msg: "Access token did not validate"}));
            return undefined;
        }
    }

    abstract hash(plaintext : string) : Promise<string>;
};
