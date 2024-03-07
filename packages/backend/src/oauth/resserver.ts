import { OAuthAuthorizationServer } from './authserver';
import jwt from 'jsonwebtoken';
import { KeyStorage } from '../storage';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { CrossauthLogger, j } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { createPublicKey, type JsonWebKey, KeyObject } from 'crypto'
import fs from 'node:fs';
import { type OpenIdConfiguration, DEFAULT_OIDCCONFIG } from '@crossauth/common';

export interface OAuthResourceServerOptions {

    /** Name for this resource server.  The `aud` field in the JWT must match this */
    resourceServerName? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAccessToken? : boolean,

    /** If persisting tokens, you need to provide a storage to persist them to */
    keyStorage? : KeyStorage,

    /** Secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtSecretKey? : string,

    /** Filename with secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKey` is required when using this kind of cipher*/
    jwtSecretKeyFile? : string,

    /** Filename for the public key if using a public key cipher for signing the JWT.  Either this or `jwtPublicKey` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKeyFile? : string,

    /** The public key if using a public key cipher for signing the JWT.  Either this or `jwtP
     * ublicKeyFile` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKey? : string,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** Set this to restrict the issuers (as set in {@link OAuthAuthorizationServer}) that will be valid in the JWT.  Required */
    oauthIssuers? : string,

    authServerBaseUri? : string;
}

export class OAuthResourceServer {
    
    protected resourceServerName : string = "";
    private persistAccessToken = false;
    private keyStorage? : KeyStorage;
    private jwtSecretKey = "";
    private jwtSecretKeyFile = "";
    private jwtPublicKeyFile = "";
    private jwtPublicKey = "";
    private clockTolerance : number = 10;
    private oauthIssuers : string[]|undefined = undefined;
    protected oidcConfig : (OpenIdConfiguration&{[key:string]:any})|undefined;
    protected authServerBaseUri = "";

    protected keys : (KeyObject|string)[] = [];

    constructor(options : OAuthResourceServerOptions = {}) {

        setParameter("authServerBaseUri", ParamType.String, this, options, "OAUTH_AUTH_SERVER_BASE_URI");
        setParameter("resourceServerName", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER", true);
        setParameter("jwtSecretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("jwtPublicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("jwtSecretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("jwtPublicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("oauthIssuers", ParamType.StringArray, this, options, "OAUTH_ISSUER", true);
        setParameter("persistAccessToken", ParamType.Boolean, this, options, "OAUTH_PERSIST_ACCESS_TOKEN");

        if (this.jwtSecretKey || this.jwtSecretKeyFile) {
            if (this.jwtPublicKey || this.jwtPublicKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric and public/private JWT keys")
            }
            if (this.jwtSecretKey && this.jwtSecretKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric key and file")
            }
            if (this.jwtSecretKeyFile) {
                this.jwtSecretKey = fs.readFileSync(this.jwtSecretKeyFile, 'utf8');
            }
        } else if ((this.jwtPublicKey || this.jwtPublicKeyFile)) {
            if (this.jwtPublicKeyFile && this.jwtPublicKey) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both public key and public key file");
            }
            if (this.jwtPublicKeyFile) {
                this.jwtPublicKey = fs.readFileSync(this.jwtPublicKeyFile, 'utf8');
            }
        } /*else {
            throw new CrossauthError(ErrorCode.Configuration, "Must specify either a JWT secret key or a public key");
        }*/
        if (this.jwtSecretKey) {
            this.keys = [this.jwtSecretKey];
        } else if (this.jwtPublicKey && typeof this.jwtPublicKey == "string") {
            this.keys = [this.jwtPublicKey];
        }
        this.keyStorage = options.keyStorage;

        if (this.persistAccessToken && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, "Must provide key storage if persisting access token");
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

        // fetch keys
        
    }

    async loadJwks(jwks? : {keys: JsonWebKey[]}) {
        if (jwks) {
            this.keys = [];
            for (let i=0; i<jwks.keys.length; ++i) {
                this.keys.push(createPublicKey({key: jwks.keys[i], format: "jwk"}));
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
            this.keys = [];
            try {
                const body = await resp.json();
                if (!("keys" in body) || !Array.isArray(body.keys)) {
                    throw new CrossauthError(ErrorCode.Connection, "Couldn't fetch keys")
                }
                for (let i=0; i<body.keys.length; ++i) {
                    try {
                        this.keys.push(createPublicKey({key: body.keys[i], format: "jwk"}));
                    } catch (e) {
                        throw new CrossauthError(ErrorCode.Connection, "Couldn't load keys");
                    }
                }
            } catch (e) {
                throw new CrossauthError(ErrorCode.Connection, "Unrecognized response from OIDC configuration endpoint");
            }
        }

    }

    async tokenAuthorized(accessToken : string) : Promise<{[key:string]: any}|undefined> {
        if (!this.keys || this.keys.length==0) {
            if (!this.oidcConfig) {
                this.loadConfig();
            }
            this.loadJwks();
        }
        const decoded = await this.validateAccessToken(accessToken);
        if (!decoded) return undefined;
        if (this.persistAccessToken && this.keyStorage) {
            try {
                const key = "access:" + Hasher.hash(decoded.payload.jti);
                const tokenInStorage = await this.keyStorage.getKey(key);
                const now = new Date();
                if (tokenInStorage.expires && tokenInStorage.expires?.getTime() < now.getTime()) {
                    CrossauthLogger.logger.error("Access token expired in storage but not in JWT");
                    return undefined;
                }
            } catch (e) {
                CrossauthLogger.logger.warn(j({msg: "Couldn't get token from database - is it valid?", hashedAccessToken: Hasher.hash(decoded.payload.jti)}))
                CrossauthLogger.logger.debug(j({err: e}));
                return undefined;
            }
        }
        if (this.oauthIssuers) {
            if ((Array.isArray(this.oauthIssuers) && !this.oauthIssuers.includes(decoded.payload.iss)) ||
                (!Array.isArray(this.oauthIssuers) && this.oauthIssuers != decoded.payload.iss)) {
                CrossauthLogger.logger.error(j({msg: `Invalid issuer ${decoded.payload.iss} in access token`, hashedAccessToken: Hasher.hash(decoded.payload.jti)}));
                return undefined;

            }
        }
        if (decoded.payload.aud) {
            if ((Array.isArray(decoded.payload.aud) && !decoded.payload.aud.includes(this.resourceServerName)) ||
                (!Array.isArray(decoded.payload.aud) && decoded.payload.aud != this.resourceServerName)) {
                    CrossauthLogger.logger.error(j({msg: `Invalid audience ${decoded.payload.aud} in access token`, hashedAccessToken: Hasher.hash(decoded.payload.jti)}));
                    return undefined;    
                }
        }
        return decoded.payload;
    }

    private async validateAccessToken(accessToken : string) : Promise<{[key:string]: any}|undefined> {

        if (this.keys.length == 0) CrossauthLogger.logger.warn("No keys loaded so cannot validate tokens");
        for (let i=0; i<this.keys.length; ++i) {
            const ret =  await new Promise((resolve, reject) => {
                jwt.verify(accessToken, this.keys[i], {clockTolerance: this.clockTolerance, complete: true}, 
                    (error: Error | null,
                    decoded: {[key:string]:any} | undefined) => {
                        if (decoded) {
                            if (decoded.payload.type == "access") {
                                resolve(decoded);
                            } else {
                                CrossauthLogger.logger.error(j({msg: "JWT is not an access token"}));
                                resolve(undefined);
                            }
                        } else if (error) { 
                            CrossauthLogger.logger.error(j({err: error}));
                            resolve(undefined);
                        } else {
                            CrossauthLogger.logger.error(j({err: error}));
                            reject(undefined);
                        }
                    });
            });
            if (ret) return ret;
        }
        return undefined;
    }
};
