import * as jose from 'jose'
import { CrossauthLogger, j } from '../logger';
import { CrossauthError, ErrorCode } from '../error';
//import { createPublicKey, type JsonWebKey, KeyObject } from 'crypto'
import { type OpenIdConfiguration, DEFAULT_OIDCCONFIG } from './wellknown';

export type Key = jose.KeyLike | Uint8Array;

export interface OAuthTokenConsumerOptions {

    /** Secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtKeyType? : string,

    /** Secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtSecretKey? : string,

    /** The public key if using a public key cipher for signing the JWT.  Either this or `jwtP
     * ublicKeyFile` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKey? : string,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** Set this to restrict the issuers (as set in {@link OAuthAuthorizationServer}) that will be valid in the JWT.  Required */
    oauthIssuers? : string,

    authServerBaseUri? : string;

    oidcConfig? : (OpenIdConfiguration&{[key:string]:any})|undefined;
}

export abstract class OAuthTokenConsumerBase {
    
    protected consumerName : string;
    protected jwtKeyType  : string | undefined;
    protected jwtSecretKey : string | undefined;
    protected jwtPublicKey  : string | undefined;
    protected clockTolerance : number = 10;
    protected oauthIssuers : string[]|undefined = undefined;
    protected authServerBaseUri = "";

    oidcConfig : (OpenIdConfiguration&{[key:string]:any})|undefined;
    keys : {[key:string]: Key} = {};

    constructor(consumerName : string, options : OAuthTokenConsumerOptions = {}) {

        this.consumerName = consumerName;

        if (options.authServerBaseUri) this.authServerBaseUri = options.authServerBaseUri;
        if (options.jwtKeyType) this.jwtKeyType = options.jwtKeyType;
        if (options.jwtSecretKey) this.jwtSecretKey = options.jwtSecretKey;
        if (options.jwtPublicKey) this.jwtPublicKey = options.jwtPublicKey;
        if (options.clockTolerance) this.clockTolerance = options.clockTolerance;
        if (options.oauthIssuers) this.oauthIssuers = options.oauthIssuers.split(/, */);
        if (options.oidcConfig) this.oidcConfig = options.oidcConfig;

        if (this.jwtPublicKey && !this.jwtKeyType) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "If specifying jwtPublic key, must also specify jwkKeyType")
        }
    }

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
                    this.loadConfig();
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

    async loadConfig(oidcConfig? : OpenIdConfiguration) {
        if (oidcConfig) {
            this.oidcConfig = oidcConfig;
            return;
        }

        if (!this.authServerBaseUri) {
            throw new CrossauthError(ErrorCode.Connection, "Couldn't get OIDC configuration.  Either set authServerBaseUri or set config manually");
        }
        let resp : Response|undefined = undefined;
        try {
            resp = await fetch(new URL("/.well-known/openid-configuration", this.authServerBaseUri));
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
        if (this.oauthIssuers) {
            if ((Array.isArray(this.oauthIssuers) && !this.oauthIssuers.includes(decoded.iss)) ||
                (!Array.isArray(this.oauthIssuers) && this.oauthIssuers != decoded.iss)) {
                CrossauthLogger.logger.error(j({msg: `Invalid issuer ${decoded.iss} in access token`, hashedAccessToken: this.hash(decoded.jti)}));
                return undefined;

            }
        }
        if (decoded.aud) {
            if ((Array.isArray(decoded.aud) && !decoded.aud.includes(this.consumerName)) ||
                (!Array.isArray(decoded.aud) && decoded.aud != this.consumerName)) {
                    CrossauthLogger.logger.error(j({msg: `Invalid audience ${decoded.aud} in access token`, hashedAccessToken: this.hash(decoded.jti)}));
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
        let key : Key|undefined = undefined;
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

    abstract hash(plaintext : string) : string;
};
