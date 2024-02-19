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

    /** JWT issuer, eg https://yoursite.com.  Required (no default) */
    oauthIssuer? : string,

    /** JWT issuer, eg https://yoursite.com.  Required (no default) */
    resourceServers? : string,

    /** PBKDF2 HMAC for hashing client secret */
    pbkdf2Digest? : string;

    /** PBKDF2 iterations for hashing client secret */
    pbkdf2Iterations? : number;

    /** PBKDF2 key length for hashing client secret */
    pbkdf2KeyLength? : number;

    /** if true, a client secret is expected in the table.  If you don't use flows for confidential clients, you do not need a secret.  Default true */
    saveClientSecret?  : boolean,

    /** `never` = client secret doesn't have to be provided (though if it is for a `token` request, it is validated).
     *  `always` = client secret always has to be provided for for `token` requests.
     *  `withoutpkce` client secret only has to be provided on `token` requests if a code challenge is not used (if it is provided though, it is checked).
     *  Default `withoutpkce`
     */
    requireClientSecret? : string,

    /** If true, only redirect Uri's registered for the client will be accepted */
    requireRedirectUriRegistration?: boolean,

    /** Key for symmetric encryption of code challenges (not the one for signing JWTs). Must be base64-url encoding of 256 bits */
    encryptionKey? : string,

    /** The algorithm to sign JWTs with.  Default `RS256` */
    jwtAlgorithm? : string,

    /** Secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKeyFile` is required when using this kind of cipher*/
    jwtSecretKey? : string,

    /** Filename with secret key if using a symmetric cipher for signing the JWT.  Either this or `jwtSecretKey` is required when using this kind of cipher*/
    jwtSecretKeyFile? : string,

    /** Filename for the private key if using a public key cipher for signing the JWT.  Either this or `jwtPrivateKey` is required when using this kind of cipher.  publicKey or publicKeyFile is also required. */
    jwtPrivateKeyFile? : string,

    /** Tthe public key if using a public key cipher for signing the JWT.  Either this or `jwtPrivateKey` is required when using this kind of cipher.  publicKey or publicKeyFile is also required. */
    jwtPrivateKey? : string,

    /** Filename for the public key if using a public key cipher for signing the JWT.  Either this or `jwtPublicKey` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKeyFile? : string,

    /** The public key if using a public key cipher for signing the JWT.  Either this or `jwtP
     * ublicKeyFile` is required when using this kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKey? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAccessToken? : boolean,

    /** Whether to issue a refresh token.  Default false */
    issueRefreshToken? : boolean,

    /** Whether to persist refresh tokens in key storage.  Default false */
    persistRefreshToken? : boolean,

    /** Whether to persist user tokens in key storage.  Default false */
    persistUserToken? : boolean,

    /** If true, access token will contain no data, just a random string.  This will turn persistAccessToken on.  Default false. */
    opaqueAccessToken? : boolean,

    /** If true, refresh token will contain no data, just a random string.  This will turn persistRefreshToken on.  Default false. */
    opaqueRefreshToken? : boolean,

    /** If true, user token will contain no data, just a random string.  This will turn persistUserToken on.  Default false. */
    opaqueUserToken? : boolean,

    /** If persisting tokens, you need to provide a storage to persist them to */
    keyStorage? : KeyStorage,

    /** Expiry for access tokens in seconds.  If null, they don't expire.  Defult 1 hour */
    accessTokenExpiry? : number | null,

    /** Expiry for refresh tokens in seconds.  If null, they don't expire.  Defult 1 day */
    refreshTokenExpiry? : number | null,

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
        private oauthIssuer : string = "";
        private resourceServers : string[]|null = null;
        private pbkdf2Digest = "sha256";
        private pbkdf2Iterations = 40000;
        private pbkdf2KeyLength = 32;
        private saveClientSecret = true;
        private requireClientSecret : "never"|"always"|"withoutpkce" = "withoutpkce";
        private requireRedirectUriRegistration = true;
        private jwtAlgorithm = "RS256";
        private jwtAlgorithmChecked : Algorithm = "RS256";
        private encryptionKey = "";
        private jwtSecretKey = "";
        private jwtPublicKey = "";
        private jwtPrivateKey = "";
        private jwtSecretKeyFile = "";
        private jwtPublicKeyFile = "";
        private jwtPrivateKeyFile = "";
        private secretOrPrivateKey = "";
        private secretOrPublicKey = "";
        private persistAccessToken = false;
        private issueRefreshToken = false;
        private persistRefreshToken = false;
        private persistUserToken = false;
        private opaqueAccessToken = false;
        private opaqueRefreshToken = false;
        private opaquetUserToken = false;
        private accessTokenExpiry : number|null = 60*60;
        private refreshTokenExpiry : number|null = 60*60*24;
        private authorizationCodeExpiry : number|null = 60*5;
        private clockTolerance : number = 10;
        private keyStorage? : KeyStorage;
        private validateScopes : boolean = false;
        private validScopes : string[] = [];
    
    constructor(clientStorage: OAuthClientStorage, options: OAuthAuthorizationServerOptions) {
        this.clientStorage = clientStorage;

        setParameter("oauthIssuer", ParamType.String, this, options, "OAUTH_ISSUER", true);
        setParameter("resourceServers", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER");
        setParameter("pbkdf2Iterations", ParamType.String, this, options, "OAUTH_PBKDF2_ITERATIONS");
        setParameter("pbkdf2Digest", ParamType.String, this, options, "OAUTH_PBKDF2_DIGEST");
        setParameter("pbkdf2KeyLength", ParamType.String, this, options, "OAUTH_PBKDF2_KEYLENGTH");
        setParameter("saveClientSecret", ParamType.String, this, options, "OAUTH_SAVE_CLIENT_SECRET");
        setParameter("requireClientSecret", ParamType.String, this, options, "OAUTH_REQUIRE_CLIENT_SECRET");
        setParameter("requireRedirectUriRegistration", ParamType.String, this, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION");
        setParameter("jwtAlgorithm", ParamType.String, this, options, "JWT_ALGORITHM");
        setParameter("encryptionKey", ParamType.String, this, options, "ENCRYPTION_KEY");
        setParameter("jwtSecretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("jwtPublicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("jwtPrivateKeyFile", ParamType.String, this, options, "JWT_PRIVATE_KEY_FILE");
        setParameter("jwtSecretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("jwtPublicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("jwtPrivateKey", ParamType.String, this, options, "JWT_PRIVATE_KEY");
        setParameter("persistAccessToken", ParamType.String, this, options, "OAUTH_PERSIST_ACCESS_TOKEN");
        setParameter("issueRefreshToken", ParamType.String, this, options, "OAUTH_ISSUE_REFRESH_TOKEN");
        setParameter("persistRefreshToken", ParamType.String, this, options, "OAUTH_PERSIST_REFRESH_TOKEN");
        setParameter("persistUserToken", ParamType.String, this, options, "OAUTH_PERSIST_USER_TOKEN");
        setParameter("opaqueAccessToken", ParamType.String, this, options, "OAUTH_OPAQUE_ACCESS_TOKEN");
        setParameter("opaqueRefreshToken", ParamType.String, this, options, "OAUTH_OPAQUE_REFRESH_TOKEN");
        setParameter("opaquetUserToken", ParamType.String, this, options, "OAUTH_OPAQUE_USER_TOKEN");
        setParameter("accessTokenExpiry", ParamType.Number, this, options, "OAUTH_ACCESS_TOKEN_EXPIRY");
        setParameter("refreshTokenExpiry", ParamType.Number, this, options, "OAUTH_REFRESH_TOKEN_EXPIRY");
        setParameter("authorizationCodeExpiry", ParamType.Number, this, options, "OAUTH_AUTHORIZATION_CODE_EXPIRY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("validateScopes", ParamType.Boolean, this, options, "OAUTH_VALIDATE_SCOPES");
        setParameter("validScopes", ParamType.StringArray, this, options, "OAUTH_VALID_SCOPES");
        
        this.jwtAlgorithmChecked = algorithm(this.jwtAlgorithm);
        
        if (this.jwtSecretKey || this.jwtSecretKeyFile) {
            if (this.jwtPublicKey || this.jwtPublicKeyFile || this.jwtPrivateKey || this.jwtPrivateKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric and public/private JWT keys")
            }
            if (this.jwtSecretKey && this.jwtSecretKeyFile) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify symmetric key and file")
            }
            if (this.jwtSecretKeyFile) {
                this.jwtSecretKey = fs.readFileSync(this.jwtSecretKeyFile, 'utf8');
            }
        } else if ((this.jwtPrivateKey || this.jwtPrivateKeyFile) && (this.jwtPublicKey || this.jwtPublicKeyFile)) {
            if (this.jwtPrivateKeyFile && this.jwtPrivateKey) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both private key and private key file");
            }
            if (this.jwtPrivateKeyFile) {
                this.jwtPrivateKey = fs.readFileSync(this.jwtPrivateKeyFile, 'utf8');
            }
            if (this.jwtPublicKeyFile && this.jwtPublicKey) {
                throw new CrossauthError(ErrorCode.Configuration, "Cannot specify both public key and public key file");
            }
            if (this.jwtPublicKeyFile) {
                this.jwtPublicKey = fs.readFileSync(this.jwtPublicKeyFile, 'utf8');
            }
        } else {
            throw new CrossauthError(ErrorCode.Configuration, "Must specify either a JWT secret key or a public and private key pair");
        }
        if (this.jwtSecretKey) {
            this.secretOrPrivateKey = this.secretOrPublicKey = this.jwtSecretKey;
        } else {
            this.secretOrPrivateKey = this.jwtPrivateKey;
            this.secretOrPublicKey = this.jwtPublicKey;
        }

        this.keyStorage = options.keyStorage;

        if (this.opaqueAccessToken) this.persistAccessToken = true;
        if (this.opaqueRefreshToken) this.persistRefreshToken = true
        if (this.opaquetUserToken) this.persistUserToken = true

        if ((this.persistAccessToken || this.persistRefreshToken || this.persistUserToken) && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, "Key storage required for persisting tokens");
        }
    }

    /**
     * The the OAuth2 authorize endpoint.  All parameters are expected to be
     * strings and have be URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     */
    async authorizeEndpoint(
        responseType : string, 
        clientId : string, 
        redirectUri : string, 
        scope : string, 
        state : string,
        code? : string,
        clientSecret? : string,
        codeChallenge? : string,
        codeChallengeMethod? : string,
        codeVerifier? : string,
        username? : string) 
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
                const code = await this.getAuthorizationCode(clientId, redirectUri, requestedScopes||[], codeChallenge, codeChallengeMethod);
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

            if (!clientSecret && !codeVerifier) {
                return {
                    error : OAuthErrorCode[OAuthErrorCode.access_denied],
                    errorDescription: "No client secret or code verifier provided when requesting access token",
                };
            }
            if (!code) {
                return {
                    error : OAuthErrorCode[OAuthErrorCode.access_denied],
                    errorDescription: "No authorization code provided when requesting access token",
                };
            }
            try {
                return await this.getAccessToken(code, clientId, clientSecret, redirectUri, codeVerifier, username);
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

    private async getAuthorizationCode(clientId: string, redirectUri : string, scopes: string[], codeChallenge? : string, codeChallengeMethod? : string) : Promise<string> {

        // if we have a challenge, check the method is valid
        if (codeChallenge && !this.encryptionKey) {
            if (!codeChallengeMethod) codeChallengeMethod = "S256";
            if (codeChallengeMethod != "S256" && codeChallengeMethod != "plain") {
                throw new CrossauthError(ErrorCode.invalid_request, "Code challenge method must be S256 or plain")
            }
                const error = new CrossauthError(ErrorCode.Configuration, "To support code challenge/verifier, you must provide the application secret");
            CrossauthLogger.logger.error(j({err: error}));
            throw new CrossauthError(ErrorCode.server_error, "Configuration error - cannot process code challenge");
        }

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
        const decodedUri = redirectUri; /*decodeURI(redirectUri.replace("+"," "));*/
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
            aud: this.oauthIssuer,
            redirect_uri: decodedUri,
            type: "code",
        };
        if (this.authorizationCodeExpiry != null) {
            payload.exp = timeCreated + this.authorizationCodeExpiry
        }
        if (codeChallenge) {
            const encryptedChallenge = Hasher.symmetricEncrypt(codeChallenge, this.encryptionKey);
            payload.challenge_method = codeChallengeMethod;
            payload.challenge = encryptedChallenge;
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

    private async getAccessToken(code : string, clientId: string, clientSecret? : string, redirectUri? : string, codeVerifier? : string, username? : string) 
        : Promise<{accessToken: string, refreshToken? : string, tokenType: string, expiresIn?: number}> {

        // make sure we have the client secret if configured to require it
        if (this.requireClientSecret == "always") {
            if (!clientSecret) {
                throw new CrossauthError(ErrorCode.access_denied, "No client secret provided");
            }
        } else if (this.requireClientSecret == "withoutpkce") {
            if (!clientSecret && !codeVerifier) {
                throw new CrossauthError(ErrorCode.access_denied, "No client secret or code verifier provided");
            }
        }

        // validate client
        let client : OAuthClient;
            try {
                client = await this.clientStorage.getClient(clientId);
                if (clientSecret) {
                    Hasher.passwordsEqual(clientSecret, client.clientSecret||"");
                }
            }
            catch (e) {
                CrossauthLogger.logger.error(j({err: e}));
                throw new CrossauthError(ErrorCode.unauthorized_client);
            }

        // validate redirect uri
        let decodedUri : string|undefined;
        if (redirectUri) {
            decodedUri = redirectUri; /*decodeURI(redirectUri.replace("+"," "));*/
            this.validateRedirectUri(decodedUri);
            if (this.requireRedirectUriRegistration && !client.redirectUri.includes(decodedUri)) {
                throw new CrossauthError(ErrorCode.invalid_request, `The redirect uri {redirectUri} is invalid`);
            }
        }

        // validate authorization code
        const authCodePayload = (await this.validateJwt(code, "code")).payload;
        let scopes = [];
        if ("scope" in authCodePayload) {
            scopes = authCodePayload.scope;
        }
        if (redirectUri) {
            if (!("redirect_uri" in authCodePayload) || authCodePayload.redirect_uri != decodedUri) {
                throw new CrossauthError(ErrorCode.access_denied, "Redirect Uri's do not match");
            }
        }
        if ("redirect_uri" in authCodePayload) {
            if (!redirectUri || authCodePayload.redirect_uri != decodedUri) {
                throw new CrossauthError(ErrorCode.access_denied, "Redirect Uri's do not match");
            }
        }
        if ((Array.isArray(authCodePayload.aud) && !authCodePayload.aud.includes(this.oauthIssuer)) ||
            (!Array.isArray(authCodePayload.aud) && authCodePayload.aud != this.oauthIssuer)) {
                throw new CrossauthError(ErrorCode.access_denied, "Authorization code not intended for this issuer");
        }

        
        // validate code verifier, if there is one
        const codeChallengeMethod = authCodePayload.challenge_method;
        if (codeChallengeMethod && !authCodePayload.challenge) {
            if (codeChallengeMethod != "plain" && codeChallengeMethod != "S256") {
                throw new CrossauthError(ErrorCode.access_denied, "Invalid code challenge/code challenge method method in authorization code");
            }
        }
        if (authCodePayload.challenge) {
            const codeChallenge = Hasher.symmetricDecrypt(authCodePayload.challenge, this.encryptionKey);
            const hashedVerifier = codeChallengeMethod == "plain" ? codeVerifier||"" : Hasher.hash(codeVerifier||"");
            if (hashedVerifier != codeChallenge) {
                throw new CrossauthError(ErrorCode.access_denied, "Code verifier is incorrect");
            }
        }



        const now = new Date();
        const timeCreated = Math.ceil(now.getTime()/1000);
        let dateAccessTokenExpires : Date|undefined;

        // create access token payload
        const accessTokenJti = Hasher.uuid();
        const accessTokenPayload : {[key:string]: any} = {
            jti: accessTokenJti,
            iat: timeCreated,
            iss: this.oauthIssuer,
            scope: scopes,
            sub: username,
            preferred_username: username,
            type: "access",
        };
        if (this.accessTokenExpiry != null) {
            accessTokenPayload.exp = timeCreated + this.accessTokenExpiry
            dateAccessTokenExpires = new Date(now.getTime()+this.accessTokenExpiry*1000 + this.clockTolerance*1000);
        }
        if (this.resourceServers) {
            accessTokenPayload.aud = this.resourceServers;
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

        // persist access token if requested
        if (this.persistAccessToken && this.keyStorage) {
            await this.keyStorage?.saveKey(
                undefined, // to avoid user storage dependency, we don't set this
                "access:"+Hasher.hash(accessTokenJti),
                now,
                dateAccessTokenExpires
            );
        }

        // create refresh token payload
        const refreshTokenJti = Hasher.uuid();
        let dateRefreshTokenExpires : Date|undefined;
        const refreshTokenPayload : {[key:string]: any} = {
            jti: refreshTokenJti,
            iat: timeCreated,
            iss: this.oauthIssuer,
            scope: scopes,
            preferred_username: username,
            sub: username,
            type: "refresh",
        };
        if (this.refreshTokenExpiry != null) {
            refreshTokenPayload.exp = timeCreated + this.refreshTokenExpiry;
            dateRefreshTokenExpires = new Date(now.getTime()+this.refreshTokenExpiry*1000 + this.clockTolerance*1000);
        }
        if (this.resourceServers) {
            refreshTokenPayload.aud = this.resourceServers;
        }

        let refreshToken : string|undefined;
        if (this.issueRefreshToken) {
            // create refresh token jwt
            refreshToken = await new Promise((resolve, reject) => {
                jwt.sign(refreshTokenPayload, this.secretOrPrivateKey, {algorithm: this.jwtAlgorithmChecked}, 
                    (error: Error | null,
                    encoded: string | undefined) => {
                        if (encoded) resolve(encoded);
                        else if (error) reject(error);
                        else reject(new CrossauthError(ErrorCode.Unauthorized, "Couldn't create jwt"));
                    });
            });

            // persist refresh token if requested
            if (this.persistRefreshToken && this.keyStorage) {
                await this.keyStorage?.saveKey(
                    undefined, // to avoid user storage dependency, we don't set this
                    "refresh:"+Hasher.hash(refreshTokenJti),
                    now,
                    dateRefreshTokenExpires
                );
            }
        }
        
        return {
            accessToken : accessToken,
            refreshToken : refreshToken,
            expiresIn : this.accessTokenExpiry==null ? undefined : this.accessTokenExpiry,
            tokenType: "Bearer",
        }
    }

    async validateJwt(code : string, type? : string) : Promise<{[key:string]: any}> {
        return  new Promise((resolve, reject) => {
            jwt.verify(code, this.secretOrPublicKey, {clockTolerance: this.clockTolerance, complete: true}, 
                (error: Error | null,
                decoded: {[key:string]:any} | undefined) => {
                    if (decoded) {
                        if (!type || decoded.payload.type == type) {
                            resolve(decoded);
                        } else {
                            reject(new CrossauthError(ErrorCode.Unauthorized, "Invalid JWT type"));
                        }
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
            requestedScopes = scope.split(" "); /*decodeURI(scope.replace("+"," ")).split(" ");*/ 
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