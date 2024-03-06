import jwt, { type Algorithm } from 'jsonwebtoken';
import { KeyStorage, UserStorage, OAuthClientStorage, OAuthAuthorizationStorage } from '../storage';
import { Authenticator } from '../auth';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import { type OpenIdConfiguration, type GrantType, type Jwks } from '@crossauth/common';
import { CrossauthError, ErrorCode, type OAuthClient, type OAuthTokenResponse } from '@crossauth/common';
import { CrossauthLogger, j, type Key, type User } from '@crossauth/common';
import { OAuthFlows } from '@crossauth/common';
import { createPublicKey, type JsonWebKey } from 'crypto'
import fs from 'node:fs';

const CLIENT_ID_LENGTH = 16;
const CLIENT_SECRET_LENGTH = 32;

const AUTHZ_CODE_PREFIX = "authz:";
const ACCESS_TOKEN_PREFIX = "access:";
const REFRESH_TOKEN_PREFIX = "refresh:";

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
    oauthPbkdf2Digest? : string;

    /** PBKDF2 iterations for hashing client secret */
    oauthPbkdf2Iterations? : number;

    /** PBKDF2 key length for hashing client secret */
    oauthPbkdf2KeyLength? : number;

    /** If true, only redirect Uri's registered for the client will be accepted */
    requireRedirectUriRegistration?: boolean,

    /** If true, the authorization code flow will require either a client secret or PKCE challenger/verifier.  Default true */
    requireClientSecretOrChallenge?: boolean,

    /** Authorization code length, before base64url-encoding.  Default 32 */
    authorizationCodeLength? : number,

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

    /** Expiry for access tokens in seconds.  If null, they don't expire.  Defult 1 hour */
    accessTokenExpiry? : number | null,

    /** Expiry for refresh tokens in seconds.  If null, they don't expire.  Defult 1 hour */
    refreshTokenExpiry? : number | null,

    /** If true, a new refresh token, with new expiry, will be issued every time the access token is refreshed.  Default true */
    rollingRefreshToken? : boolean,

    /** Expiry for authorization codes in seconds.  If null, they don't expire.  Defult 5 minutes */
    authorizationCodeExpiry? : number | null,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** If false, authorization calls without a scope will be disallowed.  Default true */
    emptyScopeIsValid? : boolean,

    /** If true, a requested scope must match one in the `validScopes` list or an error will be returned.  Default false. */
    validateScopes? : boolean,

    /** See `validateScopes`.  This should be a comma separated list, case sensitive, default empty */
    validScopes? : string,

    /** Flows to support.  A comma-separated list from {@link OAuthFlows}.  If `all`, there must be none other in the list.  Default `all` */
    validFlows? : string,

    /** Required if emptyScopeIsValid is false */
    authStorage? : OAuthAuthorizationStorage,

    /** Required if activating the password flow */
    userStorage? : UserStorage;

    /** Required if activating the password flow */
    authenticator? : Authenticator;
}

export class OAuthAuthorizationServer {

        private clientStorage : OAuthClientStorage;
        private keyStorage : KeyStorage;
        private userStorage? : UserStorage;
        private authenticator? : Authenticator;
        private authStorage? : OAuthAuthorizationStorage;

        private oauthIssuer : string = "";
        private resourceServers : string[]|null = null;
        private oauthPbkdf2Digest = "sha256";
        private oauthPbkdf2Iterations = 40000;
        private oauthPbkdf2KeyLength = 32;
        private requireRedirectUriRegistration = true;
        private requireClientSecretOrChallenge = true;
        private jwtAlgorithm = "RS256";
        private jwtAlgorithmChecked : Algorithm = "RS256";
        private authorizationCodeLength = 32;
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
        private refreshTokenExpiry : number|null = 60*60;
        private rollingRefreshToken : boolean = true;
        private authorizationCodeExpiry : number|null = 60*5;
        private clockTolerance : number = 10;
        private emptyScopeIsValid : boolean = true;
        private validateScopes : boolean = false;
        private validScopes : string[] = [];
        validFlows : string[] = ["all"];
    
    constructor(clientStorage: OAuthClientStorage, keyStorage : KeyStorage, options: OAuthAuthorizationServerOptions) {
        this.clientStorage = clientStorage;
        this.keyStorage = keyStorage;
        this.userStorage = options.userStorage;
        this.authStorage = options.authStorage;
        this.authenticator = options.authenticator;

        setParameter("oauthIssuer", ParamType.String, this, options, "OAUTH_ISSUER", true);
        setParameter("resourceServers", ParamType.String, this, options, "OAUTH_RESOURCE_SERVER");
        setParameter("oauthPbkdf2Iterations", ParamType.String, this, options, "OAUTH_PBKDF2_ITERATIONS");
        setParameter("oauthPbkdf2Digest", ParamType.String, this, options, "OAUTH_PBKDF2_DIGEST");
        setParameter("oauthPbkdf2KeyLength", ParamType.String, this, options, "OAUTH_PBKDF2_KEYLENGTH");
        setParameter("requireRedirectUriRegistration", ParamType.Boolean, this, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION");
        setParameter("requireClientSecretOrChallenge", ParamType.Boolean, this, options, "OAUTH_REQUIRE_CLIENT_SECRET_OR_CHALLENGE");
        setParameter("jwtAlgorithm", ParamType.String, this, options, "JWT_ALGORITHM");
        setParameter("authorizationCodeLength", ParamType.Number, this, options, "OAUTH_AUTHORIZATION_CODE_LENGTH");
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
        setParameter("rollingRefreshToken", ParamType.Boolean, this, options, "OAUTH_ROLLING_REFRESH_TOKEN");
        setParameter("authorizationCodeExpiry", ParamType.Number, this, options, "OAUTH_AUTHORIZATION_CODE_EXPIRY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("validateScopes", ParamType.Boolean, this, options, "OAUTH_VALIDATE_SCOPES");
        setParameter("emptyScopeIsValid", ParamType.Boolean, this, options, "OAUTH_EMPTY_SCOPE_VALID");
        setParameter("validScopes", ParamType.StringArray, this, options, "OAUTH_VALID_SCOPES");
        setParameter("validFlows", ParamType.StringArray, this, options, "OAUTH_VALID_FLOWS");
        
        if (this.validFlows.length == 1 && this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        }

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

        if (this.opaqueAccessToken) this.persistAccessToken = true;
        if (this.opaqueRefreshToken) this.persistRefreshToken = true;
        if (this.opaquetUserToken) this.persistUserToken = true;

        if ((this.persistAccessToken || this.persistRefreshToken || this.persistUserToken) && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, "Key storage required for persisting tokens");
        }

        if (this.validFlows.includes(OAuthFlows.Password) && (!this.userStorage || !this.authenticator)) {
            throw new CrossauthError(ErrorCode.Configuration, "If password flow is enabled, userStorage and authenticator must be provided");
        }
    }

    /**
     * The the OAuth2 authorize endpoint.  All parameters are expected to be
     * strings and have be URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     */
    async authorizeGetEndpoint({
            responseType, 
            clientId, 
            redirectUri, 
            scope, 
            state,
            codeChallenge,
            codeChallengeMethod,
            user,
        } : {
            responseType : string, 
            clientId : string, 
            redirectUri : string, 
            scope? : string, 
            state : string,
            codeChallenge? : string,
            codeChallengeMethod? : string,
            user? : User}) 
    : Promise<{
        code? : string,
        state? : string,
        error? : string,
        error_description? : string,
    }> {
        // validate responseType (because OAuth requires a different error for this)
        if (responseType != "code") {
            return {
                error: "unsupported_response_type",
                error_description: "Unsupported response type " + responseType,
            };
        }

        // validate client
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClient(clientId);
        }
        catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return {error: "unauthorized_client", error_description: "Client is not authorized"};
        }


        // validate flow type
        const flow = this.inferFlowFromGet(responseType, codeChallenge);
        if (!flow || !(this.validFlows.includes(flow))) {
            return {
                error: "access_denied",
                error_description: "Unsupported flow type " + flow,
            };
        }
        if (!client.validFlow.includes(flow)) {
            return {
                error: "unauthorized_client",
                error_description: "Client does not support " + flow,
            };
        }

        // validate scopes
        const {scopes, error: scopeError, error_description: scopeErrorDesciption} = await this.validateAndPersistScope(clientId, scope, user);
        if (scopeError) return {error: scopeError, error_description: scopeErrorDesciption};

        // validate state
        try {
            this.validateState(state);
        } catch (e) {
            return {
                error: "invalid_request",
                error_description: "Invalid state",
            };
        }

        if (responseType == "code") {
            return await this.getAuthorizationCode(client, redirectUri, scopes, state, codeChallenge, codeChallengeMethod, user);
        } else {

            return {
                error : "unsupported_response_type",
                error_description: `Invalid response_type ${responseType}`,
            };

        }
    }

    async hasAllScopes(clientId : string, user : User|undefined, requestedScopes: (string|null)[]) : Promise<boolean> {
        if (!this.authStorage) return false;
        const existingScopes = await this.authStorage.getAuthorizations(clientId, user?.id);
        const existingRequestedScopes = requestedScopes.filter((scope) => existingScopes.includes(scope));
        return existingRequestedScopes.length == requestedScopes.length;
    }

    async validateAndPersistScope(clientId : string, scope? : string,user? : User) : Promise<{scopes?: string[]|undefined, error?: string, error_description?: string}> {
        // validate scopes
        let scopes : string[]|undefined;
        let scopesIncludingNull : (string|null)[]|undefined;
        if (!scope && !this.emptyScopeIsValid) {
            return {error: "invalid_scope", error_description: "Must provide at least one scope"};
        }
        if (scope) {
            const {error: scopeError, errorDescription: scopeErrorDesciption, scopes: requestedScopes} = this.validateScope(scope);
            scopes = requestedScopes;
            scopesIncludingNull = requestedScopes;
            if (scopeError) return {error: scopeError, error_description: scopeErrorDesciption??"Unknown error"};      
        } else {
            scopesIncludingNull = [null];
        }
        if (this.authStorage) {
            try {
                const newScopes = scopesIncludingNull??[];
                const existingScopes = await this.authStorage.getAuthorizations(clientId, user?.id);
                const updatedScopes = [...new Set([...existingScopes, ...newScopes])];
                CrossauthLogger.logger.debug(j({msg: "Updating authorizations for " + clientId + " to " + updatedScopes}));
                this.authStorage.updateAuthorizations(clientId, user?.id, updatedScopes);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return { error: "server_error", error_description: "Couldn't save scope"};
            }
        }
        return {scopes: scopes};
    }
    /**
     * The the OAuth2 authorize endpoint.  All parameters are expected to be
     * strings and have be URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     */
    async tokenPostEndpoint({
        grantType, 
        clientId, 
        scope, 
        code,
        clientSecret,
        codeVerifier,
        refreshToken,
        username,
        password,
    } : {
        grantType : string, 
        clientId : string, 
        scope? : string, 
        code? : string,
        clientSecret? : string,
        codeVerifier? : string,
        refreshToken? : string,
        username? : string,
        password? : string}) 
    : Promise<OAuthTokenResponse> {

        const flow = this.inferFlowFromPost(grantType, codeVerifier);

        // get client
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClient(clientId);
        } catch (e) {
            return {
                error: "access_denied",
                error_description: "client id does not exist",
            }
        }

        // throw an error if client authentication is required not not present
        let authenticateClient = false;
        switch (flow) {
            case OAuthFlows.AuthorizationCode:
            case OAuthFlows.AuthorizationCodeWithPKCE:
                authenticateClient = (client.confidential || client.clientSecret != undefined || clientSecret != undefined);
                break;
            case OAuthFlows.ClientCredentials:
                authenticateClient = true;
                break;
            case OAuthFlows.Password:
                authenticateClient = (client.confidential || client.clientSecret != undefined || clientSecret != undefined);
                break;
            case OAuthFlows.RefreshToken:
                authenticateClient = (client.confidential || client.clientSecret != undefined || clientSecret != undefined);
                break;
            case OAuthFlows.DeviceCode:
                authenticateClient = (client.confidential || client.clientSecret != undefined || clientSecret != undefined);
                break;
        }
        if (authenticateClient && (client.clientSecret==undefined || clientSecret==undefined)) {
            return {
                error: "access_denied",
                error_description: "Client secret is required for this client",
            }
        }

        // validate flow type
        if (!flow || !(this.validFlows.includes(flow))) {
            return {
                error: "access_denied",
                error_description: "Unsupported flow type " + flow,
            };
        }
        if (client && !client.validFlow.includes(flow)) {
            return {
                error: "unauthorized_client",
                error_description: "Client does not support " + flow,
            };
        }

        // validate scopes (move to client credentials)
        /*if (scope) {
            const {error: scopeError, errorDescription: scopeErrorDesciption} = this.validateScope(scope);
            if (scopeError) return {error: scopeError, errorDescription: scopeErrorDesciption};        
        }*/

        // determine whether we are also creating a refresh token
        let createRefreshToken = false;
        if (this.issueRefreshToken && flow != OAuthFlows.RefreshToken) {
            createRefreshToken = true;
        }
        if (this.issueRefreshToken && flow == OAuthFlows.RefreshToken && this.rollingRefreshToken) {
            createRefreshToken = true;
        }

        if (grantType == "authorization_code") {

            // validate secret/challenge
            if (this.requireClientSecretOrChallenge && (client && client.clientSecret && !clientSecret) && !codeVerifier) {
                return {
                    error : "access_denied",
                    error_description: "Must provide either a client secret or use PKCE",
                };
            }

            if (client && client.clientSecret && !clientSecret) {
                return {
                    error : "access_denied",
                    error_description: "No client secret or code verifier provided for authorization coode flow",
                };
            }
            if (!code) {
                return {
                    error : "access_denied",
                    error_description: "No authorization code provided for authorization code flow",
                };
            }
            return await this.getAccessToken(client, code, clientSecret, codeVerifier, undefined, createRefreshToken);

        } else if (grantType == "refresh_token") {
    
            if (!this.validRefreshToken(refreshToken??"")) {
                return {
                    error: "access_denied",
                    error_description: "Refresh token is invalid",
                }
            }
            return await this.getAccessToken(client, undefined, clientSecret, codeVerifier, undefined, createRefreshToken);

        } else if (grantType == "client_credentials") {

            // validate scopes
            const {scopes, error: scopeError, error_description: scopeErrorDesciption} = await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) return {error: scopeError, error_description: scopeErrorDesciption};
    
            return await this.getAccessToken(client, undefined, clientSecret, codeVerifier, scopes, createRefreshToken);

        } else if (grantType == "password") {

            // validate scopes
            const {scopes, error: scopeError, error_description: scopeErrorDesciption} = await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) return {error: scopeError, error_description: scopeErrorDesciption};
    
            // validate username and password
            if (!username || !password) {
                return {
                    error: "access_denied",
                    error_description: "Username and/or password not provided for password flow",
                }
            }
            let user : User|undefined = undefined;
            try {
                if (!this.userStorage || !this.authenticator) {
                    // already checked in constructor but VS code doesn't know
                    return {error: "server_error", error_description: "Password authentication not configured"};
                }
                const {user: user1, secrets} = await this.userStorage.getUserByUsername(username);
                await this.authenticator.authenticateUser(user1, secrets, {password: password});
                user = user1;
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "access_denied",
                    error_description: "Username and/or password do not match",
                }
            }
            return await this.getAccessToken(client, undefined, clientSecret, codeVerifier, scopes, createRefreshToken, user);

        } else {

            return {
                error : "invalid_request",
                error_description: `Invalid grant_type ${grantType}`,
            };

        }
    }

    inferFlowFromGet(
        responseType : string, 
        codeChallenge? : string,
    ) : string|undefined {

        if (responseType == "code") {
            if (codeChallenge) return OAuthFlows.AuthorizationCodeWithPKCE;
            return OAuthFlows.AuthorizationCode;
        }
        return undefined;
    }

    inferFlowFromPost(
        grantType : string, 
        codeVerifier? : string) : string|undefined {

        if (grantType == "authorization_code") {
            if (codeVerifier) return OAuthFlows.AuthorizationCodeWithPKCE;
            return OAuthFlows.AuthorizationCode;
        } else if (grantType == "client_credentials") {
            return OAuthFlows.ClientCredentials;
        } else if (grantType == "refresh_token") {
            return OAuthFlows.RefreshToken;
        } else if (grantType == "device_code") {
            return OAuthFlows.DeviceCode;
        } else if (grantType == "password") {
            return OAuthFlows.Password;
        }
        return undefined;

    }

    private async getAuthorizationCode(client: OAuthClient, redirectUri : string, scopes: string[]|undefined, state: string, codeChallenge? : string, codeChallengeMethod? : string, user? : User) : Promise<{code? : string, state? : string, error? : string, error_description? : string}> {

        // if we have a challenge, check the method is valid
        if (codeChallenge) {
            if (!codeChallengeMethod) codeChallengeMethod = "S256";
            if (codeChallengeMethod != "S256" && codeChallengeMethod != "plain") {
                return {error: "invalid_request", error_description: "Code challenge method must be S256 or plain"};
            }
        }

        // validate redirect uri
        const decodedUri = redirectUri; /*decodeURI(redirectUri.replace("+"," "));*/
        OAuthAuthorizationServer.validateUri(decodedUri);
        if (this.requireRedirectUriRegistration && !client.redirectUri.includes(decodedUri)) {
            return {error: "invalid_request", error_description: `The redirect uri ${redirectUri} is invalid`};
        }


        // create authorization code and data to store with the key
        const created = new Date();
        const expires = this.authorizationCodeExpiry ? new Date(created.getTime() + this.authorizationCodeExpiry*1000 + this.clockTolerance*1000) : undefined;
        const authzData : {[key:string]: any} = {
        }
        if (scopes) {
            authzData.scope = scopes;
        }
        if (codeChallenge) {
            authzData.challengeMethod = codeChallengeMethod;
            // we store this as a hash for security.  If S256 is used, that will be a second hash
            authzData.challenge = Hasher.hash(codeChallenge);
        }
        if (user) {
            authzData.username = user.username;
            authzData.userId = user.userId;
        }
        const authzDataString = JSON.stringify(authzData);

        // save the code in key storage
        let success = false;
        let authzCode = "";
        for (let i=0; i<10 && !success; ++i) {
            try {
                authzCode = Hasher.randomValue(this.authorizationCodeLength);
                this.keyStorage.saveKey(undefined, AUTHZ_CODE_PREFIX+Hasher.hash(authzCode), created, expires, authzDataString);
                success = true;
            } catch (e) {
                CrossauthLogger.logger.debug(`Attempt nmumber${i} at creating a unique authozation code failed`)
            }
        }
        if (!success) {
            throw new CrossauthError(ErrorCode.KeyExists, "Couldn't create a authorization code");
        }

        return {code: authzCode, state: state};
    }

    private async getAccessToken(client: OAuthClient, code? : string, clientSecret? : string, codeVerifier? : string,  scopes? : string[], issueRefreshToken = false, user? : User) 
        : Promise<OAuthTokenResponse> {

        // validate client secret
        let passwordCorrect = true;
        try {
            if (client.clientSecret!=undefined) { // we validated this before so if authentication is required, it will not be undefined
                passwordCorrect = await Hasher.passwordsEqual(clientSecret??"", client.clientSecret??"");
            }
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            const message = e instanceof CrossauthError ? e.message : "Couldn't validate client";
            return {error: "server_error", error_description: message};
        }
        if (!passwordCorrect) return {error: "access_denied", error_description: "Invalid client secret"};

        // validate authorization code
        let authzData : {
            scope? : string[],
            challenge? : string,
            challengeMethod? : string,
            userId? : number|string,
            username? : string,
            [key:string] : any, // so having anything else stored doesn't raise an exception
        } = {};

        if (code) {

            // recover scope, challenge and user from data persisted with authorization code
            let key : Key|undefined;
            try {
                key = await this.keyStorage.getKey(AUTHZ_CODE_PREFIX+Hasher.hash(code));
                authzData = KeyStorage.decodeData(key.data);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {error: "access_denied", error_description: "Invalid or expired authorization code"};
            }
            try {
                await this.keyStorage.deleteKey(key.value);
            } catch (e) {
                CrossauthLogger.logger.warn(j({err: e, msg: "Couldn't delete authorization code from storatge", clientId: client?.clientId}));
            }
            scopes = authzData.scope;
        }
        if (user) {
            authzData.username = user.username;
        }
        
        // validate code verifier, if there is one
        if (authzData.challengeMethod && !authzData.challenge) {
            if (authzData.challengeMethod != "plain" && authzData.challengeMethod != "S256") {
                return {error: "access_denied", error_description:  "Invalid code challenge/code challenge method method for authorization code"};
            }
        }
        if (authzData.challenge) {
            const hashedVerifier = authzData.challengeMethod == "plain" ? codeVerifier??"" : Hasher.sha256(codeVerifier??"");
            // we store the challenge in hashed form for security, so if S256 is used this will be a second hash
            if (Hasher.hash(hashedVerifier) != authzData.challenge) {
                return {error: "access_denied", error_description:   "Code verifier is incorrect"};
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
            sub: authzData.username,
            type: "access",
        };
        if (scopes) {
            accessTokenPayload.scope = scopes;
        }
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
                ACCESS_TOKEN_PREFIX+Hasher.hash(accessTokenJti),
                now,
                dateAccessTokenExpires
            );
        }

        let newRefreshToken : string|undefined = undefined;

        if (issueRefreshToken) {
            // create refresh token payload
            const refreshTokenJti = Hasher.uuid();
            let dateRefreshTokenExpires : Date|undefined;
            const refreshTokenPayload : {[key:string]: any} = {
                jti: refreshTokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                sub: authzData.username,
                type: "refresh",
                client_id: client.clientId,
            };
            if (scopes) {
                refreshTokenPayload.scope = scopes;
            }
            if (this.refreshTokenExpiry != null) {
                refreshTokenPayload.exp = timeCreated + this.refreshTokenExpiry;
                dateRefreshTokenExpires = new Date(now.getTime()+this.refreshTokenExpiry*1000 + this.clockTolerance*1000);
            }
            if (this.resourceServers) {
                refreshTokenPayload.aud = this.resourceServers;
            }

            // create refresh token jwt
            newRefreshToken = await new Promise((resolve, reject) => {
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
                    REFRESH_TOKEN_PREFIX+Hasher.hash(refreshTokenJti),
                    now,
                    dateRefreshTokenExpires
                );
            }
        }
        
        return {
            access_token : accessToken,
            refresh_token : newRefreshToken,
            expires_in : this.accessTokenExpiry==null ? undefined : this.accessTokenExpiry,
            token_type: "Bearer",
        }
    }

    async validAuthenticationCode(token : string) : Promise<{[key:string]: any}|undefined> {
        try {
            const decoded = await this.validateJwt(token, "refresh");
            if (this.persistRefreshToken) {
                const hash = "refresh:" + Hasher.hash(decoded.jti);
                await this.keyStorage.getKey(hash);
            }
            return decoded;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return undefined;
        }
    }

    async validRefreshToken(token : string) : Promise<{[key:string]: any}|undefined> {
        try {
            const decoded = await this.validateJwt(token, "refresh");
            if (this.persistRefreshToken) {
                const hash = "refresh:" + Hasher.hash(decoded.payload.jti);
                await this.keyStorage.getKey(hash);
            }
            return decoded;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return undefined;
        }
    }

    async validAccessToken(token : string) : Promise<{[key:string]: any}|undefined> {
        try {
            const decoded = await this.validateJwt(token, "access");
            if (this.persistAccessToken) {
                const hash = "access:" + Hasher.hash(decoded.payload.jti);
                await this.keyStorage.getKey(hash);
            }
            return decoded;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return undefined;
        }
    }

    private async validateJwt(code : string, type? : string) : Promise<{[key:string]: any}> {
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
            const errorCode = "invalid_scope";
            const errorDescription = `Invalid scope ${scope}`;
            CrossauthLogger.logger.debug(j({err: CrossauthError.fromOAuthError(errorCode, errorDescription)}));
            return {
                error : errorCode,
                errorDescription: errorDescription,
            };
        }
        if (this.validateScopes) {
            let ret : {error: string, errorDescription: string}|undefined;
            requestedScopes.forEach((requestedScope) => {
                if (!(this.validScopes.includes(requestedScope))) {
                    const errorCode = "invalid_scope";
                    const errorDescription = `Illegal scope ${requestedScope}`;
                    CrossauthLogger.logger.debug(j({err: CrossauthError.fromOAuthError(errorCode, errorDescription)}));
                    ret = {
                        error : errorCode,
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

    async createClient(name : string, redirectUri : string[], validFlow? : string[], confidential=true) : Promise<OAuthClient> {
        const clientId = OAuthAuthorizationServer.randomClientId();
        let clientSecret : string|undefined = undefined;
        if (confidential) {
            const plaintext = OAuthAuthorizationServer.randomClientSecret();
            clientSecret = await Hasher.passwordHash(plaintext, {
                encode: true,
                iterations: this.oauthPbkdf2Iterations,
                keyLen: this.oauthPbkdf2KeyLength,
                digest: this.oauthPbkdf2Digest,
            });
        }
        redirectUri.forEach((uri) => {
            OAuthAuthorizationServer.validateUri(uri);
        });
        if (!validFlow) {
            validFlow = OAuthFlows.allFlows();
        }
        const client = {
            clientId: clientId,
            clientSecret: clientSecret,
            clientName : name,
            redirectUri : redirectUri,
            confidential: confidential,
            validFlow: validFlow,
        }
        return await this.clientStorage.createClient(client);
    }

    static validateUri(uri : string) {
        let valid = false;
        try {
            const validUri = new URL(uri);
            valid = validUri.hash.length == 0;
        } catch (e) {
            // test if its a valid relative url
            try {
                const validUri = new URL(uri);
                valid = validUri.hash.length == 0;
            } catch (e2) {
                CrossauthLogger.logger.debug(j({err: e}));
            }
        }
        if (!valid) {
            throw CrossauthError.fromOAuthError("invalid_request", `Invalid redirect Uri ${uri}`);
        }
    }

    redirectUri(redirectUri : string, code : string, state : string) : string {
        const sep = redirectUri.includes("?") ? "&" : "?";
        return `${redirectUri}${sep}code=${code}&state=${state}`;
    }

    oidcConfiguration({
        authorizeEndpoint, 
        tokenEndpoint,
        jwksUri,
        additionalClaims} : {
            authorizeEndpoint? : string,
            tokenEndpoint? : string,
            jwksUri : string,
            additionalClaims? : string[],
        }) : OpenIdConfiguration {

        let grantTypes : GrantType[] = [];
        this.validFlows.forEach((flow) => {
            const grantType = OAuthFlows.grantType(flow);
            if (grantType) grantTypes.push(grantType);
        })

        const jwtAlgorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
        ];
        if (!additionalClaims) additionalClaims = [];
        return {
            issuer: this.oauthIssuer,
            authorization_endpoint: new URL(authorizeEndpoint??"authorize", this.oauthIssuer).toString(),
            token_endpoint: new URL(tokenEndpoint??"token", this.oauthIssuer).toString(),
            token_endpoint_auth_methods_supported: ["client_secret_post"],
            jwks_uri: new URL(jwksUri??"jwks", this.oauthIssuer).toString(),
            response_types_supported: ["code"],
            response_modes_supported: ["query"],
            grant_types_supported: grantTypes,
            token_endpoint_auth_signing_alg_values_supported: jwtAlgorithms,
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: jwtAlgorithms,
            claims_supported: ["iss", "sub", "aud", "jti", "iat", "type", ...additionalClaims],
            request_uri_parameter_supported: true,
            require_request_uri_registration: this.requireRedirectUriRegistration,
        };
    }

    jwks() : Jwks {
        let keys : JsonWebKey[] = [];
        if (this.jwtPublicKey) {
            const publicKey = createPublicKey(this.jwtPublicKey).export({format: "jwk"});
            keys.push(publicKey)
        }
        return { keys };
    }

    private validateState(state : string) {
        if (!(/^[A-Za-z0-9_-]+$/.test(state))) {
            throw CrossauthError.fromOAuthError("invalid_request");
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

    validateAuthorizeParameters({
        response_type, 
        client_id, 
        redirect_uri, 
        scope, 
        state,
        code_challenge,
        code_challenge_method,
    } : {
        response_type : string, 
        client_id : string, 
        redirect_uri : string, 
        scope? : string, 
        state : string,
        code_challenge? : string,
        code_challenge_method? : string}) : {error? : string, error_description? : string} {

        let error_description : string|undefined = undefined;
        if (!/^[A-Za-z0-9_-]+$/.test(response_type)) error_description = "response_type is invalid";
        else if (!/^[A-Za-z0-9_-]+$/.test(client_id)) error_description = "client_id is invalid";
        else if (scope && !/^[A-Za-z0-9_+ -]+$/.test(scope)) error_description = "scope is invalid";
        else if (!/^[A-Za-z0-9_-]+$/.test(state)) error_description = "state is invalid";
        else if (code_challenge && !/^[A-Za-z0-9_-]+$/.test(code_challenge)) error_description = "code_challenge is invalid";
        else if (code_challenge_method && !/^[A-Za-z0-9_-]+$/.test(code_challenge_method)) error_description = "code_challenge_method is invalid";
        try {
            new URL(redirect_uri);
        } catch (e) {
            error_description = "redirect_uri is invalid";
        }
        if (!redirect_uri || redirect_uri.includes('#')) error_description = "redirect_uri is invalid";
        if (error_description) return {error: "invalid_request", error_description: error_description};
        return {};
    }
}