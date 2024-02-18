import jwt, { Algorithm } from 'jsonwebtoken';
import { KeyStorage, OAuthClientStorage } from '../storage';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { CrossauthError, ErrorCode, OAuthClient, OAuthErrorCode } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import fs from 'node:fs';

const CLIENT_ID_LENGTH = 16;
const CLIENT_SECRET_LENGTH = 16;

function algorithm(value : string) : Algorithm {
    switch (value) {
        case "HS256":
        case "HS384":
        case "HS512":
        case "RS256":
        case "RS384":
        case "RS512":
        case "ES256":
        case "ES384":
        case "ES512":
        case "PS256":
        case "PS384":
        case "PS512":
        case "none":
            return value;
    }
    throw new CrossauthError(ErrorCode.Configuration, "Invalid JWT signing algorithm " + value)
}

export interface OAuthAuthorizationServerOptions {

    /** PBKDF2 HMAC for hashing client secret */
    pbkdf2Digest? : string;

    /** PBKDF2 iterations for hashing client secret */
    pbkdf2Iterations? : number;

    /** PBKDF2 key length for hashing client secret */
    pbkdf2KeyLength? : number;

    /** if true, a client secret is expected in the table.  If you don't use flows for confidential clients, you do not need a secret.  Default true */
    saveClientSecret?  : boolean,

    /** If true, only redirect Uri's registered for the client will be accepted */
    requireRedirectUriRegistration?: boolean,

    /** The algorithm to sign JWTs with.  Default `RS256` */
    jwtAlgorithm? : string,

    /** Secret key if using a symmetric cipher for signing the JWT.  Either this or `secretKeyFile` is required when using this kind of cipher*/
    secretKey? : string,

    /** Filename with secret key if using a symmetric cipher for signing the JWT.  Either this or `secretKey` is required when using this kind of cipher*/
    secretKeyFile? : string,

    /** Filename for the private key if using a public key cipher for signing the JWT.  Either this or `privateKey` is required when using this kind of cipher.  publicKey or publicKeyFile is also required. */
    privateKeyFile? : string,

    /** Tthe public key if using a public key cipher for signing the JWT.  Either this or `privateKey` is required when using this kind of cipher.  publicKey or publicKeyFile is also required. */
    privateKey? : string,

    /** Filename for the public key if using a public key cipher for signing the JWT.  Either this or `publicKey` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    publicKeyFile? : string,

    /** The public key if using a public key cipher for signing the JWT.  Either this or `publicKeyFile` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    publicKey? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAcccessToken? : boolean,

    /** Whether to persist refresh tokens in key storage.  Default false */
    peristRefreshToken? : boolean,

    /** Whether to persist user tokens in key storage.  Default false */
    persistUserToken? : boolean,

    /** If true, access token will contain no data, just a random string.  This will turn persistAccessToken on.  Default false. */
    opaqueAcccessToken? : boolean,

    /** If true, refresh token will contain no data, just a random string.  This will turn persistRefreshToken on.  Default false. */
    opaqueRefreshToken? : boolean,

    /** If true, user token will contain no data, just a random string.  This will turn persistUserToken on.  Default false. */
    opaqueUserToken? : boolean,

    /** If persisting tokens, you need to provide a storage to persist them to */
    keyStorage? : KeyStorage,

    /** Expiry for access tokens in seconds.  If null, they don't expire.  Defult 1 hour */
    accessTokenExpiry? : number | null,

    /** Expiry for authorization codes in seconds.  If null, they don't expire.  Defult 5 minutes */
    authorizationCodeExpiry? : number | null,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** If true, a requested scope must match one in the `validScopes` list or an error will be returned.  Default false. */
    validateScopes? : boolean,

    /** See `validateScopes`.  This should be a comma separated list, case sensitive, default empty */
    validScopes? : string,
}

export class OAuthAuthorizationServer {

        private clientStorage : OAuthClientStorage;
        private pbkdf2Digest = "sha256";
        private pbkdf2Iterations = 40000;
        private pbkdf2KeyLength = 32;
        private saveClientSecret = true;
        private requireRedirectUriRegistration = true;
        private jwtAlgorithm = "RS256";
        private jwtAlgorithmChecked : Algorithm = "RS256";
        private secretKey = "";
        private publicKey = "";
        private privateKey = "";
        private secretKeyFile = "";
        private publicKeyFile = "";
        private privateKeyFile = "";
        private secretOrPrivateKey = "";
        private secretOrPublicKey = "";
        private persistAcccessToken = false;
        private peristRefreshToken = false;
        private persistUserToken = false;
        private opaqueAcccessToken = false;
        private opaqueRefreshToken = false;
        private opaquetUserToken = false;
        private accessTokenExpiry : number|null = 60*60;
        private authorizationCodeExpiry : number|null = 60*5;
        private clockTolerance : number = 10;
        private keyStorage? : KeyStorage;
        private validateScopes : boolean = false;
        private validScopes : string[] = [];
    
    constructor(clientStorage: OAuthClientStorage, options: OAuthAuthorizationServerOptions) {
        this.clientStorage = clientStorage;

        setParameter("pbkdf2Digest", ParamType.String, this, options, "OAUTH_PBKDF2_DIGEST");
        setParameter("pbkdf2Iterations", ParamType.String, this, options, "OAUTH_PBKDF2_ITERATIONS");
        setParameter("pbkdf2KeyLength", ParamType.String, this, options, "OAUTH_PBKDF2_KEYLENGTH");
        setParameter("saveClientSecret", ParamType.String, this, options, "OAUTH_SAVE_CLIENT_SECRET");
        setParameter("requireRedirectUriRegistration", ParamType.String, this, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION");
        setParameter("jwtAlgorithm", ParamType.String, this, options, "JWT_ALGORITHM");
        setParameter("secretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("publicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("privateKeyFile", ParamType.String, this, options, "JWT_PRIVATE_KEY_FILE");
        setParameter("secretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("publicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("privateKey", ParamType.String, this, options, "JWT_PRIVATE_KEY");
        setParameter("persistAcccessToken", ParamType.String, this, options, "OAUTH_PERSIST_ACCESS_TOKEN");
        setParameter("peristRefreshToken", ParamType.String, this, options, "OAUTH_PERSIST_REFRESH_TOKEN");
        setParameter("persistUserToken", ParamType.String, this, options, "OAUTH_PERSIST_USER_TOKEN");
        setParameter("opaqueAcccessToken", ParamType.String, this, options, "OAUTH_OPAQUE_ACCESS_TOKEN");
        setParameter("opaqueRefreshToken", ParamType.String, this, options, "OAUTH_OPAQUE_REFRESH_TOKEN");
        setParameter("opaquetUserToken", ParamType.String, this, options, "OAUTH_OPAQUE_USER_TOKEN");
        setParameter("accessTokenExpiry", ParamType.Number, this, options, "OAUTH_ACCESS_TOKEN_EXPIRY");
        setParameter("authorizationCodeExpiry", ParamType.Number, this, options, "OAUTH_AUTHORIZATION_CODE_EXPIRY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("validateScopes", ParamType.Boolean, this, options, "OAUTH_VALIDATE_SCOPES");
        setParameter("validScopes", ParamType.StringArray, this, options, "OAUTH_VALID_SCOPES");
        
        this.jwtAlgorithmChecked = algorithm(this.jwtAlgorithm);
        
        if (this.secretKey || this.secretKeyFile) {
            if (this.publicKey || this.publicKeyFile || this.privateKey || this.privateKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric and public/private JWT keys")
            }
            if (this.secretKey && this.secretKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric key and file")
            }
            if (this.secretKeyFile) {
                this.secretKey = fs.readFileSync(this.secretKeyFile, 'utf8');
            }
        } else if ((this.privateKey || this.privateKeyFile) && (this.publicKey || this.publicKeyFile)) {
            if (this.privateKeyFile && this.privateKey) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both private key and private key file");
            }
            if (this.privateKeyFile) {
                this.privateKey = fs.readFileSync(this.privateKeyFile, 'utf8');
            }
            if (this.publicKeyFile && this.publicKey) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both private key and private key file");
            }
            if (this.publicKeyFile) {
                this.publicKey = fs.readFileSync(this.publicKeyFile, 'utf8');
            }
        } else {
            throw new CrossauthError(ErrorCode.Configuration, "Must specify either a JWT secret key or a public and private key pair");
        }
        if (this.secretKey) {
            this.secretOrPrivateKey = this.secretOrPublicKey = this.secretKey;
        } else {
            this.secretOrPrivateKey = this.privateKey;
            this.secretOrPublicKey = this.publicKey;
        }

        this.keyStorage = options.keyStorage;

        if (this.opaqueAcccessToken) this.persistAcccessToken = true;
        if (this.opaqueRefreshToken) this.peristRefreshToken = true
        if (this.opaquetUserToken) this.persistUserToken = true

        if ((this.persistAcccessToken || this.peristRefreshToken || this.persistUserToken) && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, "Key storage required for persisting tokens");
        }
    }

    async authorizeEndpoint(
        responseType : string, 
        clientId : string, 
        redirectUri : string, 
        scope : string, 
        state : string,
        code? : string,
        clientSecret? : string) 
    : Promise<{
        code? : string,
        state? : string,
        accessToken? : string,
        refreshToken? : string,
        tokenType? : string,
        expiresIn? : number,
        error? : string,
        errorDescription? : string,
    }> {
        // validate scopes
        const {error: scopeError, errorDescription: scopeErrorDesciption, scopes: requestedScopes} = this.validateScope(scope);
        if (scopeError) return {error: scopeError, errorDescription: scopeErrorDesciption};        

        // validate state
        try {
            this.validateState(state);
        } catch (e) {
            return {
                error: OAuthErrorCode[OAuthErrorCode.invalid_request],
                errorDescription: "Invalid state",
            };
        }

        if (responseType == "code") {

            try {
                const code = await this.getAuthorizationCode(clientId, redirectUri, requestedScopes||[]);
                return {
                    code: code,
                    state: state,
                };
            }
            catch (e) {
                // error creating authorization code given clientId and redirect uri
                let errorCode = OAuthErrorCode.server_error;
                let errorDescription = (e instanceof Error) ? e.message : "An unknown error occurred";
                if (e instanceof CrossauthError) {
                    errorCode = e.oauthCode;
                    errorDescription = e.message;
                }
                CrossauthLogger.logger.error(j({err: e}));
                return {
                    error : OAuthErrorCode[errorCode],
                    errorDescription: errorDescription,
                };
            }

        } else if (responseType == "token") {

            if (!clientSecret) {
                return {
                    error : OAuthErrorCode[OAuthErrorCode.access_denied],
                    errorDescription: "No client secret provided when requesting access token",
                };
            }
            if (!code) {
                return {
                    error : OAuthErrorCode[OAuthErrorCode.access_denied],
                    errorDescription: "No authorization code provided when requesting access token",
                };
            }
            try {
                const {accessToken, refreshToken, expiresIn} = await this.getAccessToken(code, clientId, clientSecret, redirectUri);
                return {
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    expiresIn: expiresIn,
                };
            }
            catch (e) {
                // error creating access token given clientId, client secret redirect uri
                let errorCode = OAuthErrorCode.server_error;
                let errorDescription = (e instanceof Error) ? e.message : "An unknown error occurred";
                if (e instanceof CrossauthError) {
                    errorCode = e.oauthCode;
                    errorDescription = e.message;
                }
                CrossauthLogger.logger.error(j({err: e}));
                return {
                    error : OAuthErrorCode[errorCode],
                    errorDescription: errorDescription,
                };
            }

        } else {

            const errorCode = ErrorCode.unsupported_response_type
            const errorDescription = `Invalid response_type ${responseType}`;
            CrossauthLogger.logger.error(j({err: new CrossauthError(errorCode, errorDescription)}));
            return {
                error : OAuthErrorCode[errorCode],
                errorDescription: errorDescription,
            };

        }
    }

    private async getAuthorizationCode(clientId: string, redirectUri : string, scopes: string[]) : Promise<string> {

        // validate client
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClient(clientId);
        }
        catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.unauthorized_client);
        }

        // validate redirect uri
        const decodedUri = decodeURI(redirectUri.replace("+"," "));
        this.validateRedirectUri(decodedUri);
        if (this.requireRedirectUriRegistration && !client.redirectUri.includes(decodedUri)) {
            throw new CrossauthError(ErrorCode.invalid_request, `The redirect uri {redirectUri} is invalid`);
        }

        // create response payload
        const timeCreated = Math.ceil(new Date().getTime()/1000);
        const payload : {[key:string]: any} = {
            jti: Hasher.uuid(),
            iat: timeCreated,
            scope: scopes,
            redirectUri: decodedUri,
        };
        if (this.authorizationCodeExpiry != null) {
            payload.exp = timeCreated + this.authorizationCodeExpiry
        }

        // sign and return token
        return  new Promise((resolve, reject) => {
            jwt.sign(payload, this.secretOrPrivateKey, {algorithm: this.jwtAlgorithmChecked}, 
                (error: Error | null,
                encoded: string | undefined) => {
                    if (encoded) resolve(encoded);
                    else if (error) reject(error);
                    else reject(new CrossauthError(ErrorCode.Unauthorized, "Couldn't create jwt"));
                });
        });
    }

    private async getAccessToken(code : string, clientId: string, clientSecret : string, redirectUri? : string) 
        : Promise<{accessToken: string, refreshToken : string, expiresIn?: number}> {

        // validate client
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClient(clientId);
            Hasher.passwordsEqual(clientSecret, client.clientSecret||"")
        }
        catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.unauthorized_client);
        }

        // validate redirect uri
        let decodedUri : string|undefined;
        if (redirectUri) {
            decodedUri = decodeURI(redirectUri.replace("+"," "));
            this.validateRedirectUri(decodedUri);
            if (this.requireRedirectUriRegistration && !client.redirectUri.includes(decodedUri)) {
                throw new CrossauthError(ErrorCode.invalid_request, `The redirect uri {redirectUri} is invalid`);
            }
        }

        // validate authorization code
        const authCodePayload = (await this.validateJwt(code)).payload;
        let scopes = [];
        if ("scope" in authCodePayload) {
            scopes = authCodePayload.scope;
        }
        if (redirectUri) {
            if (!("redirectUri" in authCodePayload) || authCodePayload.redirectUri != decodedUri) {
                throw new CrossauthError(ErrorCode.access_denied, "Redirect Uri's do not match");
            }
        }
        if ("redirectUri" in authCodePayload) {
            if (!redirectUri || authCodePayload.redirectUri != decodedUri) {
                throw new CrossauthError(ErrorCode.access_denied, "Redirect Uri's do not match");
            }
        }

        const timeCreated = Math.ceil(new Date().getTime()/1000);

        // create access token payload
        const accessTokenPayload : {[key:string]: any} = {
            jti: Hasher.uuid(),
            iat: timeCreated,
            scope: scopes,
        };
        if (this.accessTokenExpiry != null) {
            accessTokenPayload.exp = timeCreated + this.accessTokenExpiry
        }

        // create access token jwt
        const accessToken : string = await new Promise((resolve, reject) => {
            jwt.sign(accessTokenPayload, this.secretOrPrivateKey, {algorithm: this.jwtAlgorithmChecked}, 
                (error: Error | null,
                encoded: string | undefined) => {
                    if (encoded) resolve(encoded);
                    else if (error) reject(error);
                    else reject(new CrossauthError(ErrorCode.Unauthorized, "Couldn't create jwt"));
                });
        });

        // create refresh token payload
        const refreshTokenPayload : {[key:string]: any} = {
            jti: Hasher.uuid(),
            iat: timeCreated,
            scope: scopes,
        };
        if (this.accessTokenExpiry != null) {
            refreshTokenPayload.exp = timeCreated + this.accessTokenExpiry
        }

        // create access token jwt
        const refreshToken : string = await new Promise((resolve, reject) => {
            jwt.sign(refreshTokenPayload, this.secretOrPrivateKey, {algorithm: this.jwtAlgorithmChecked}, 
                (error: Error | null,
                encoded: string | undefined) => {
                    if (encoded) resolve(encoded);
                    else if (error) reject(error);
                    else reject(new CrossauthError(ErrorCode.Unauthorized, "Couldn't create jwt"));
                });
        });

        return {
            accessToken : accessToken,
            refreshToken : refreshToken,
            expiresIn : this.accessTokenExpiry==null ? undefined : this.accessTokenExpiry,
        }
    }

    async validateJwt(code : string) : Promise<{[key:string]: any}> {
        return  new Promise((resolve, reject) => {
            jwt.verify(code, this.secretOrPublicKey, {clockTolerance: this.clockTolerance, complete: true}, 
                (error: Error | null,
                decoded: {[key:string]:any} | undefined) => {
                    if (decoded) {
                        resolve(decoded);
                    } else if (error) { 
                        CrossauthLogger.logger.debug(j({err: error}));
                        reject(new CrossauthError(ErrorCode.Unauthorized, "Invalid JWT signature"));
                    } else {
                        reject(new CrossauthError(ErrorCode.Unauthorized, "Couldn't create jwt"));
                    }
                });
        });

    }

    private validateScope(scope : string) : {error?: string, errorDescription? : string, scopes? : string[]} {
        let requestedScopes = [];
        try {
            requestedScopes = decodeURI(scope.replace("+"," ")).split(" ");
        } catch (e) {
            const errorCode = ErrorCode.invalid_scope;
            const errorDescription = `Invalid scope ${scope}`;
            CrossauthLogger.logger.error(j({err: new CrossauthError(errorCode, errorDescription)}));
            return {
                error : OAuthErrorCode[errorCode],
                errorDescription: errorDescription,
            };
        }
        if (this.validateScopes) {
            let ret : {error: string, errorDescription: string}|undefined;
            requestedScopes.forEach((requestedScope) => {
                if (!(this.validScopes.includes(requestedScope))) {
                    const errorCode = ErrorCode.invalid_scope;
                    const errorDescription = `Illegal scope ${requestedScope}`;
                    CrossauthLogger.logger.error(j({err: new CrossauthError(errorCode, errorDescription)}));
                    ret = {
                        error : OAuthErrorCode[errorCode],
                        errorDescription: errorDescription,
                    };
                }
            });   
            if (ret) return ret; 
        }
        return {
            scopes: requestedScopes,
        }

    }

    async createClient(name : string, redirectUri : string[]) : Promise<OAuthClient> {
        const clientId = OAuthAuthorizationServer.randomClientId();
        let clientSecret : string|undefined = undefined;
        if (this.saveClientSecret) {
            const plaintext = OAuthAuthorizationServer.randomClientSecret();
            clientSecret = await Hasher.passwordHash(plaintext, {
                encode: true,
                iterations: this.pbkdf2Iterations,
                keyLen: this.pbkdf2KeyLength,
                digest: this.pbkdf2Digest,
            });
        }
        redirectUri.forEach((uri) => {
            this.validateRedirectUri(uri);
        });
        const client = {
            clientId: clientId,
            clientSecret: clientSecret,
            clientName : name,
            redirectUri : redirectUri,
        }
        return await this.clientStorage.createClient(client);
    }

    private validateRedirectUri(uri : string) {
        let valid = false;
        try {
            const validUri = new URL(uri);
            valid = validUri.hash.length == 0;
        } catch (e) {
            // test if its a valid relative url
            try {
                const validUri = new URL(uri, "https://example.com");
                valid = validUri.hash.length == 0;
            } catch (e2) {
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        if (!valid) {
            throw new CrossauthError(ErrorCode.invalid_request, `Invalid redirect Uri ${uri}`);
        }
    }

    redirectUri(redirectUri : string, code : string, state : string) : string {
        return `${redirectUri}?code=${code}&stte=${state}`;
    }

    private validateState(state : string) {
        if (!(/^[A-Za-z0-9_-]+$/.test(state))) {
            throw new CrossauthError(ErrorCode.invalid_request);
        }
    }

    /**
     * Create a random OAuth client id
     */
    static randomClientId() : string {
        return Hasher.randomValue(CLIENT_ID_LENGTH)
    }

     /**
     * Create a random OAuth client secret
     */
    static randomClientSecret() : string {
        return Hasher.randomValue(CLIENT_SECRET_LENGTH)
    }
}