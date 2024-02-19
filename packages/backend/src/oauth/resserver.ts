import { OAuthAuthorizationServer } from './authserver';
import jwt from 'jsonwebtoken';
import { KeyStorage } from '../storage';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { CrossauthLogger, j } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import fs from 'node:fs';

export interface OAuthResourceServerOptions {

    /** Name for this resource server.  The `aud` field in the JWT must match this */
    resourceServerName? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAcccessToken? : boolean,

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
}

export class OAuthResourceServer {
    
    private resourceServerName : string = "";
    private persistAcccessToken = false;
    private keyStorage? : KeyStorage;
    private jwtSecretKey = "";
    private jwtSecretKeyFile = "";
    private jwtPublicKeyFile = "";
    private jwtPublicKey = "";
    private secretOrPublicKey = "";
    private clockTolerance : number = 10;
    private oauthIssuers : string[]|undefined = undefined;

    constructor(options : OAuthResourceServerOptions = {}) {

        setParameter("resourceServerName", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER", true);
        setParameter("jwtSecretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("jwtPublicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("jwtSecretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("jwtPublicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("oauthIssuers", ParamType.StringArray, this, options, "OAUTH_ISSUER", true);

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
        } else {
            throw new CrossauthError(ErrorCode.Configuration, "Must specify either a JWT secret key or a public key");
        }
        if (this.jwtSecretKey) {
            this.secretOrPublicKey = this.jwtSecretKey;
        } else {
            this.secretOrPublicKey = this.jwtPublicKey;
        }
        this.keyStorage = options.keyStorage;

        if (this.persistAcccessToken && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, "Must provide key storage if persisting access token");
        }
    }

    async authorized(accessToken : string) : Promise<{[key:string]: any}|undefined> {
        const decoded = await this.validateAccessToken(accessToken);
        if (!decoded) return undefined;
        if (this.persistAcccessToken && this.keyStorage) {
            const key = "access:" + Hasher.hash(decoded.payload.jti);
            try {
                const tokenInStorage = await this.keyStorage.getKey(key)
                const now = new Date().getTime();
                if (tokenInStorage.expires && tokenInStorage.expires?.getTime() < now) {
                    CrossauthLogger.logger.error("Access token expired in storage but not in JWT");
                    return undefined;
                }
            } catch (e) {
                CrossauthLogger.logger.error(j({err: e, msg: "Access token doesn't exist in storage"}));
                return undefined;
            }
        }
        if (this.oauthIssuers) {
            if ((Array.isArray(this.oauthIssuers) && !this.oauthIssuers.includes(decoded.payload.iss)) ||
                (!Array.isArray(this.oauthIssuers) && this.oauthIssuers != decoded.payload.iss)) {
                CrossauthLogger.logger.error(j({msg: `Invalid issuer ${decoded.payload.iss} in access token`}));
                return undefined;

            }
        }
        if (decoded.payload.aud) {
            if ((Array.isArray(decoded.payload.aud) && !decoded.payload.aud.includes(this.resourceServerName)) ||
                (!Array.isArray(decoded.payload.aud) && decoded.payload.aud != this.resourceServerName)) {
                    CrossauthLogger.logger.error(j({msg: `Invalid audience ${decoded.payload.aud} in access token`}));
                    return undefined;    
                }
        }
        return decoded;
    }

    private async validateAccessToken(accessToken : string) : Promise<{[key:string]: any}|undefined> {
        return  new Promise((resolve, reject) => {
            jwt.verify(accessToken, this.secretOrPublicKey, {clockTolerance: this.clockTolerance, complete: true}, 
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
    }
};
