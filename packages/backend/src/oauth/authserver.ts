import jwt, { type Algorithm } from 'jsonwebtoken';
import {
    KeyStorage,
    UserStorage,
    OAuthClientStorage,
    OAuthAuthorizationStorage} from '../storage';
import { Authenticator } from '../auth';
import { setParameter, ParamType } from '../utils';
import { Hasher } from '../hasher';
import type { OpenIdConfiguration, GrantType, Jwks, MfaAuthenticatorResponse } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import type  { OAuthClient, OAuthTokenResponse } from '@crossauth/common';
import { CrossauthLogger, j, type Key, type User } from '@crossauth/common';
import { OAuthFlows } from '@crossauth/common';
import { createPublicKey, type JsonWebKey } from 'crypto'
import fs from 'node:fs';

const CLIENT_ID_LENGTH = 16;
const CLIENT_SECRET_LENGTH = 32;

const AUTHZ_CODE_PREFIX = "authz:";
const ACCESS_TOKEN_PREFIX = "access:";
const REFRESH_TOKEN_PREFIX = "refresh:";
const MFA_TOKEN_PREFIX = "omfa:";

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
    throw new CrossauthError(ErrorCode.Configuration, 
        "Invalid JWT signing algorithm " + value)
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

    /** If true, only redirect Uri's registered for the client will be 
     * accepted */
    requireRedirectUriRegistration?: boolean,

    /** If true, the authorization code flow will require either a client 
     * secret or PKCE challenger/verifier.  Default true */
    requireClientSecretOrChallenge?: boolean,

    /** Authorization code length, before base64url-encoding.  Default 32 */
    authorizationCodeLength? : number,

    /** The algorithm to sign JWTs with.  Default `RS256` */
    jwtAlgorithm? : string,

    /** Secret key if using a symmetric cipher for signing the JWT.  
     * Either this or `jwtSecretKeyFile` is required when using this kind of 
     * cipher*/
    jwtSecretKey? : string,

    /** Filename with secret key if using a symmetric cipher for signing the 
     * JWT.  Either this or `jwtSecretKey` is required when using this kind 
     * of cipher*/
    jwtSecretKeyFile? : string,

    /** Filename for the private key if using a public key cipher for 
     * signing the JWT.  Either this or `jwtPrivateKey` is required when 
     * using this kind of cipher.  publicKey or publicKeyFile is also 
     * required. */
    jwtPrivateKeyFile? : string,

    /** Tthe public key if using a public key cipher for signing the JWT.  
     * Either this or `jwtPrivateKey` is required when using this kind of 
     * cipher.  publicKey or publicKeyFile is also required. */
    jwtPrivateKey? : string,

    /** Filename for the public key if using a public key cipher for signing 
     * the JWT.  Either this or `jwtPublicKey` is required when using this 
     * kind of cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKeyFile? : string,

    /** The public key if using a public key cipher for signing the JWT.  
     * Either this or `jwtPublicKeyFile` is required when using this kind of 
     * cipher.  privateKey or privateKeyFile is also required. */
    jwtPublicKey? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAccessToken? : boolean,

    /** Whether to issue a refresh token.  Default false */
    issueRefreshToken? : boolean,

    /** Whether to persist refresh tokens in key storage.  Default false */
    persistRefreshToken? : boolean,

    /** Whether to persist user tokens in key storage.  Default false */
    persistUserToken? : boolean,

    /** If true, access token will contain no data, just a random string.  
     * This will turn persistAccessToken on.  Default false. */
    opaqueAccessToken? : boolean,

    /** If true, refresh token will contain no data, just a random string.  
     * This will turn persistRefreshToken on.  Default false. */
    opaqueRefreshToken? : boolean,

    /** If true, user token will contain no data, just a random string.  
     * This will turn persistUserToken on.  Default false. */
    opaqueUserToken? : boolean,

    /** Expiry for access tokens in seconds.  If null, they don't expire.  
     * Defult 1 hour */
    accessTokenExpiry? : number | null,

    /** Expiry for refresh tokens in seconds.  If null, they don't expire.  
     * Defult 1 hour */
    refreshTokenExpiry? : number | null,

    /** If true, a new refresh token, with new expiry, will be issued every 
     * time the access token is refreshed.  Default true */
    rollingRefreshToken? : boolean,

    /** Expiry for authorization codes in seconds.  If null, they don't 
     * expire.  Defult 5 minutes */
    authorizationCodeExpiry? : number | null,

    /** Expiry for authorization codes in seconds.  If null, they don't 
     * expire.  Defult 5 minutes */
    mfaTokenExpiry? : number | null,

    /** Number of seconds tolerance when checking expiration.  Default 10 */
    clockTolerance? : number,

    /** If false, authorization calls without a scope will be disallowed.  
     * Default true */
    emptyScopeIsValid? : boolean,

    /** If true, a requested scope must match one in the `validScopes` list 
     * or an error will be returned.  Default false. */
    validateScopes? : boolean,

    /** See `validateScopes`.  This should be a comma separated list, case 
     * sensitive, default empty */
    validScopes? : string,

    /** Flows to support.  A comma-separated list from {@link OAuthFlows}.  
     * If `all`, there must be none other in the list.  Default `all` */
    validFlows? : string,

    /** Required if emptyScopeIsValid is false */
    authStorage? : OAuthAuthorizationStorage,

    /** Required if activating the password flow */
    userStorage? : UserStorage;

    /** Required if activating the password flow */
    authenticators? : {[key:string] : Authenticator};

    idTokenClaims? : string;
}

export class OAuthAuthorizationServer {

        private clientStorage : OAuthClientStorage;
        private keyStorage : KeyStorage;
        private userStorage? : UserStorage;
        private authenticators : {[key:string] : Authenticator} = {};
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
        private mfaTokenExpiry : number|null = 60*5;
        private clockTolerance : number = 10;
        private emptyScopeIsValid : boolean = true;
        private validateScopes : boolean = false;
        private validScopes : string[] = [];
        private idTokenClaims : string[] = [];
        private idTokenClaimsMap : {[key:string]: string} = {};
        private idTokenClaimsAll : boolean = false;
        validFlows : string[] = ["all"];
    
    constructor(clientStorage: OAuthClientStorage,
        keyStorage: KeyStorage,
        options: OAuthAuthorizationServerOptions) {
        this.clientStorage = clientStorage;
        this.keyStorage = keyStorage;
        this.userStorage = options.userStorage;
        this.authStorage = options.authStorage;
        if (options.authenticators) {
            this.authenticators = options.authenticators;
        }

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
        setParameter("mfaTokenExpiry", ParamType.Number, this, options, "OAUTH_MFA_TOKEN_EXPIRY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("validateScopes", ParamType.Boolean, this, options, "OAUTH_VALIDATE_SCOPES");
        setParameter("emptyScopeIsValid", ParamType.Boolean, this, options, "OAUTH_EMPTY_SCOPE_VALID");
        setParameter("validScopes", ParamType.StringArray, this, options, "OAUTH_VALID_SCOPES");
        setParameter("validFlows", ParamType.StringArray, this, options, "OAUTH_VALID_FLOWS");
        setParameter("idTokenClaims", ParamType.StringArray, this, options, "OAUTH_ID_TOKEN_CLAIMS");
        if (this.idTokenClaims.length == 1 && this.idTokenClaims[0] == "all") {
            this.idTokenClaimsAll = true;
        } else {
            for (let claim of this.idTokenClaims) {
                const pair = claim.split(":");
                if (pair.length != 2) {
                    throw new CrossauthError(ErrorCode.Configuration, 
                        "Id token claims must be a string of claim:fieldName separated by spaces");
                    }
                this.idTokenClaimsMap[pair[0]] = pair[1];
            }        
        }

        if (this.validFlows.length == 1 &&
            this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        }

        this.jwtAlgorithmChecked = algorithm(this.jwtAlgorithm);
        
        if (this.jwtSecretKey || this.jwtSecretKeyFile) {
            if (this.jwtPublicKey || this.jwtPublicKeyFile || 
                this.jwtPrivateKey || this.jwtPrivateKeyFile) {
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
        } else if ((this.jwtPrivateKey || this.jwtPrivateKeyFile) && 
                   (this.jwtPublicKey || this.jwtPublicKeyFile)) {
            if (this.jwtPrivateKeyFile && this.jwtPrivateKey) {
                throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify both private key and private key file");
            }
            if (this.jwtPrivateKeyFile) {
                this.jwtPrivateKey = fs.readFileSync(this.jwtPrivateKeyFile, 
                    'utf8');
            }
            if (this.jwtPublicKeyFile && this.jwtPublicKey) {
                throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify both public key and public key file");
            }
            if (this.jwtPublicKeyFile) {
                this.jwtPublicKey = fs.readFileSync(this.jwtPublicKeyFile, 
                    'utf8');
            }
        } else {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Must specify either a JWT secret key or a public and private key pair");
        }
        if (this.jwtSecretKey) {
            this.secretOrPrivateKey = this.secretOrPublicKey =
                this.jwtSecretKey;
        } else {
            this.secretOrPrivateKey = this.jwtPrivateKey;
            this.secretOrPublicKey = this.jwtPublicKey;
        }

        if (this.opaqueAccessToken) this.persistAccessToken = true;
        if (this.opaqueRefreshToken) this.persistRefreshToken = true;
        if (this.opaquetUserToken) this.persistUserToken = true;

        if ((this.persistAccessToken || this.persistRefreshToken || 
            this.persistUserToken) && !this.keyStorage) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Key storage required for persisting tokens");
        }

        if ((this.validFlows.includes(OAuthFlows.Password) || 
             this.validFlows.includes(OAuthFlows.PasswordMfa) ) 
             && (!this.userStorage || Object.keys(this.authenticators).length == 0)) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "If password flow or password MFA flow is enabled, userStorage and authenticators must be provided");
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
        // validate responseType (because OAuth requires a different error 
        // for this)
        const responseTypesSupported = this.responseTypesSupported();
        if (!responseTypesSupported.includes(responseType)) {
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
            return {error: "unauthorized_client", 
                    error_description: "Client is not authorized"};
        }

        // validate scopes
        const { scopes,
            error: scopeError,
            error_description: scopeErrorDesciption } 
            = await this.validateAndPersistScope(clientId, scope, user);
        if (scopeError) return {
            error: scopeError,
            error_description: scopeErrorDesciption
        };


        // validate flow type
        const flow = 
            this.inferFlowFromGet(responseType, scopes||[], codeChallenge);
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
            return await this.getAuthorizationCode(client,
                redirectUri,
                scopes,
                state,
                codeChallenge,
                codeChallengeMethod,
                user);
        } else {

            return {
                error : "unsupported_response_type",
                error_description: `Invalid response_type ${responseType}`,
            };

        }
    }

    async hasAllScopes(clientId: string,
        user: User | undefined,
        requestedScopes: (string | null)[]) : Promise<boolean> {
        if (!this.authStorage) return false;
        const existingScopes = 
            await this.authStorage.getAuthorizations(clientId, user?.id);
        const existingRequestedScopes = 
            requestedScopes.filter((scope) => existingScopes.includes(scope));
        return existingRequestedScopes.length == requestedScopes.length;
    }

    async validateAndPersistScope(clientId: string,
        scope?: string,
        user?: User): Promise<{
            scopes?: string[] | undefined,
            error?: string,
            error_description?: string
}> {
        // validate scopes
        let scopes : string[]|undefined;
        let scopesIncludingNull : (string|null)[]|undefined;
        if (!scope && !this.emptyScopeIsValid) {
            return {
                error: "invalid_scope",
                error_description: "Must provide at least one scope"
            };
        }
        if (scope) {
            const { error: scopeError,
                errorDescription: scopeErrorDesciption,
                scopes: requestedScopes } = this.validateScope(scope);
            scopes = requestedScopes;
            scopesIncludingNull = requestedScopes;
            if (scopeError) {
                return {
                    error: scopeError,
                    error_description: scopeErrorDesciption ?? "Unknown error"
                };     
            } 
        } else {
            scopesIncludingNull = [null];
        }
        if (this.authStorage) {
            try {
                const newScopes = scopesIncludingNull??[];
                const existingScopes 
                    = await this.authStorage.getAuthorizations(clientId,
                        user?.id);
                const updatedScopes = 
                    [...new Set([...existingScopes, ...newScopes])];
                CrossauthLogger.logger.debug(j({
                    msg: "Updating authorizations for " + clientId + " to " + updatedScopes}));
                this.authStorage.updateAuthorizations(clientId,
                    user?.id,
                    updatedScopes);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "server_error",
                    error_description: "Couldn't save scope"
                };
            }
        }
        return {scopes: scopes};
    }

    private async authenticateClient(flow: string,
        client: OAuthClient,
        clientSecret?: string) :
        Promise<{error?: string, error_description? : string}>
    {
        let authenticateClient = false;
        switch (flow) {
            case OAuthFlows.AuthorizationCode:
            case OAuthFlows.AuthorizationCodeWithPKCE:
                authenticateClient = (client.confidential==true || 
                    client.clientSecret != undefined || 
                    clientSecret != undefined);
                break;
            case OAuthFlows.ClientCredentials:
                authenticateClient = true;
                break;
            case OAuthFlows.Password:
            case OAuthFlows.PasswordMfa:
                authenticateClient = (client.confidential==true || 
                    client.clientSecret != undefined || 
                    clientSecret != undefined);
                break;
            case OAuthFlows.RefreshToken:
                authenticateClient = (client.confidential==true || 
                    client.clientSecret != undefined || 
                    clientSecret != undefined);
                break;
            case OAuthFlows.DeviceCode:
                authenticateClient = (client.confidential==true || 
                    client.clientSecret != undefined || 
                    clientSecret != undefined);
                break;
        }
        if (authenticateClient && (client.clientSecret==undefined || 
            clientSecret==undefined)) {
            return {
                error: "access_denied",
                error_description: "Client secret is required for this client",
            }
        }
        if (authenticateClient && (!clientSecret || !client.clientSecret)) {
            return {
                error: "access_denied",
                error_description: "Client is confidential but either secret not passed or is missing in database",
            }
        }
        if (authenticateClient) {
            const passwordCorrect = 
                await Hasher.passwordsEqual(clientSecret??"", 
                    client.clientSecret??"");
            if (!passwordCorrect) {
                return {
                    error: "access_denied",
                    error_description: "Incorrect client secret",
                }

            }
        }
        return {};

    }

    async getClient(clientId : string) : 
        Promise<{
            client?: OAuthClient,
            error?: string,
            error_description?: string
    }> {
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClient(clientId);
            return {client};
        } catch (e) {
            return {
                error: "access_denied",
                error_description: "client id does not exist",
            }
        }

    }

    /**
     * The the OAuth2 authorize endpoint.  All parameters are expected to be
     * strings and have be URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     */
    async tokenEndpoint({
        grantType, 
        clientId, 
        scope, 
        code,
        clientSecret,
        codeVerifier,
        refreshToken,
        username,
        password,
        mfaToken,
        oobCode,
        bindingCode,
        otp,
    } : {
        grantType : string, 
        clientId : string, 
        scope? : string, 
        code? : string,
        clientSecret? : string,
        codeVerifier? : string,
        refreshToken? : string,
        username? : string,
        password? : string,
        mfaToken? : string,
        oobCode? : string,
        bindingCode?: string,
        otp? : string}) 
    : Promise<OAuthTokenResponse> {

        const flow = this.inferFlowFromPost(grantType, codeVerifier);
        if (!flow) return {
            error: "server_error",
            error_description: "Unable to determine OAuth flow type",

        }

        // get client
        const clientResponse = await this.getClient(clientId);
        if (!clientResponse.client) return clientResponse;    
        const client = clientResponse.client;

        // throw an error if client authentication is required not not present
        const clientAuthentication = 
            await this.authenticateClient(flow, client, clientSecret);
        if (clientAuthentication.error) return clientAuthentication;

        // validate flow type
        if (flow == OAuthFlows.Password) {
            // special case - this flow is indistiguishable from PasswordMfa 
            // by looking at the request
            if (!(this.validFlows.includes(flow)) && 
                !(this.validFlows.includes(OAuthFlows.PasswordMfa))) {
                return {
                    error: "access_denied",
                    error_description: "Unsupported flow type " + flow,
                };    
            }
        }
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
            const {error: scopeError, errorDescription: scopeErrorDesciption} = 
                this.validateScope(scope);
            if (scopeError) return {error: scopeError, 
                errorDescription: scopeErrorDesciption};        
        }*/

        // determine whether we are also creating a refresh token
        let createRefreshToken = false;
        if (this.issueRefreshToken && flow != OAuthFlows.RefreshToken) {
            createRefreshToken = true;
        }
        if (this.issueRefreshToken && flow == OAuthFlows.RefreshToken && 
            this.rollingRefreshToken) {
            createRefreshToken = true;
        }

        let user : User|undefined;
        if (grantType == "authorization_code") {

            // validate secret/challenge
            if (this.requireClientSecretOrChallenge && 
                (client && client.clientSecret && !clientSecret) && 
                !codeVerifier) {
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
            return await this.getAccessToken({
                client,
                code,
                clientSecret,
                codeVerifier,
                issueRefreshToken: createRefreshToken
            });

        } else if (grantType == "refresh_token") {
    
            if (!this.validRefreshToken(refreshToken??"")) {
                return {
                    error: "access_denied",
                    error_description: "Refresh token is invalid",
                }
            }
            return await this.getAccessToken({
                client,
                clientSecret,
                codeVerifier,
                issueRefreshToken: createRefreshToken
            });

        } else if (grantType == "client_credentials") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) {
                return {
                            error: scopeError,
                            error_description: scopeErrorDesciption
                };
            }
    
            return await this.getAccessToken({
                client,
                clientSecret,
                codeVerifier,
                scopes,
                issueRefreshToken: createRefreshToken
            });

        } else if (grantType == "password") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) {
                return {
                    error: scopeError,
                    error_description: scopeErrorDesciption
                };
            }
    
            // validate username and password
            if (!username || !password) {
                return {
                    error: "access_denied",
                    error_description: "Username and/or password not provided for password flow",
                }
            }
            try {
                if (!this.userStorage) {
                    // already checked in constructor but VS code doesn't know
                    return {
                        error: "server_error",
                        error_description: "Password authentication not configured"
                    };
                }
                const {user: user1, secrets} = 
                    await this.userStorage.getUserByUsername(username);
                const factor1Authenticator = this.authenticators[user1.factor1];
                if (!factor1Authenticator || 
                    !(factor1Authenticator.secretNames()
                        .includes("password"))) {
                    return {
                        error: "access_denied",
                        error_description: "Password flow used but factor 1 authenticator does not accept passwords",
                    }
                }
                await factor1Authenticator.authenticateUser(user1,
                    secrets,
                    { password: password });
                user = user1;
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "access_denied",
                    error_description: "Username and/or password do not match",
                }
            }
            if (user.factor2) {
                return await this.createMfaRequest(user);
            }
            return await this.getAccessToken({
                client, 
                clientSecret, 
                codeVerifier, 
                scopes, 
                issueRefreshToken: createRefreshToken, 
                user});

        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-otp") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) {
                return {
                    error: scopeError,
                    error_description: scopeErrorDesciption
                };
            }
 
            // validate otp code
            if (!otp) {
                return {
                    error: "access_denied",
                    error_description: "OTP not provided"
                };
            }
            // validate otp code
            if (!mfaToken) {
                return {
                    error: "access_denied",
                    error_description: "MFA token not provided"
                };
            }

            const mfa = await this.validateMfaToken(mfaToken);
            if (!mfa.user || !mfa.key) {
                return {
                    error: "access_denied",
                    error_description: "Invalid MFA token"
                };
            }
            const authenticator = this.authenticators[mfa.user.factor2];
            if (!authenticator || !this.userStorage) {
                return {
                    error: "access_denied",
                    error_description: "MFA type is not supported for OAuth",
                }
            }
            try {
                const {secrets} = 
                    await this.userStorage.getUserById(mfa.user.id);
                await authenticator.authenticateUser(mfa.user,
                    secrets,
                    { otp });
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "access_denied",
                    error_description: "Invalid OTP",
                }
            }

            try {
                this.keyStorage.deleteKey(mfa.key.value);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.warn(j({
                    cerr: e,
                    msg: "Couldn't delete mfa token",
                    hashedMfaToken: mfa.key.value
                }))
            }
    
            return await this.getAccessToken({
                client, 
                clientSecret, 
                codeVerifier, 
                scopes,
                issueRefreshToken: createRefreshToken, 
                user: mfa.user});

        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-oob") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(clientId, scope, undefined);
            if (scopeError) {
                return {
                    error: scopeError,
                    error_description: scopeErrorDesciption
                };
            }

            // validate oob code and binding code
            if (!oobCode || !bindingCode) {
                return {
                    error: "access_denied",
                    error_description: "OOB code or binding codfe not provided"
                };
            }

            // validate MFA token code
            if (!mfaToken) {
                return {
                    error: "access_denied",
                    error_description: "MFA token not provided"
                };
            }

            const mfa = await this.validateMfaToken(mfaToken);
            if (!mfa.user || !mfa.key) {
                return {
                    error: "access_denied",
                    error_description: "Invalid MFA token"
                };
            }
            const authenticator = this.authenticators[mfa.user.factor2];
            if (!authenticator || !this.userStorage) {
                return {
                    error: "access_denied",
                    error_description: "MFA type is not supported for OAuth",
                }
            }
            try {
                const {secrets} = 
                    await this.userStorage.getUserById(mfa.user.id);
                    const omfadata = KeyStorage.decodeData(mfa.key.data)["omfa"];
                    if (!omfadata || !omfadata.otp || !omfadata.oobCode) {
                        return {
                            error: "server_error",
                            error_description: "Cannot retrieve email OTP",
                        };
                    }
                    if (omfadata.oobCode != oobCode) {
                        return {
                            error: "access_denied",
                            error_description: "Invalid OOB code",
                        };
                    }
                    await authenticator.authenticateUser(mfa.user,
                    {...secrets, otp: omfadata.otp, expiry: mfa.key.expires?.getTime()},
                    { otp: bindingCode });
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "access_denied",
                    error_description: "Invalid OTP",
                }
            }
    
            try {
                this.keyStorage.deleteKey(mfa.key.value);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.warn(j({
                    cerr: e,
                    msg: "Couldn't delete mfa token",
                    hashedMfaToken: mfa.key.value
                }))
            }

            return await this.getAccessToken({
                client, 
                clientSecret, 
                codeVerifier, 
                scopes,
                issueRefreshToken: createRefreshToken, 
                user: mfa.user});

        } else {

            return {
                error : "invalid_request",
                error_description: `Invalid grant_type ${grantType}`,
            };

        }
    }

    async createMfaRequest(user: User): Promise<{
        mfa_token: string,
        error: string,
        error_description: string
    }> {
        const mfaToken = Hasher.randomValue(16);
        const mfaKey = MFA_TOKEN_PREFIX + Hasher.hash(mfaToken);
        const now = new Date();
        try {
            await this.keyStorage.saveKey(
                user.id, 
                mfaKey, 
                now, 
                this.mfaTokenExpiry ?  
                    (new Date(now.getTime() + (this.mfaTokenExpiry+this.clockTolerance)*1000)) : 
                    undefined,
                JSON.stringify({omfaaid: user.factor2})
            );
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({
                cerr: ce,
                msg: "Couldn't save MFA token",
            }));
        }
        return {
            mfa_token: mfaToken,
            error: "mfa_required",
            error_description: "Multifactor authentication required",
        };
    }

    private async validateMfaToken(mfaToken : string) :
        Promise<{
            user?: User,
            key? : Key,
            error?: string,
            error_description?: string
        }> {

            let user : User|undefined;
            let key : Key|undefined;
            try {
                const mfaKey = MFA_TOKEN_PREFIX + Hasher.hash(mfaToken);
                key = await this.keyStorage.getKey(mfaKey);
                if (!key.userId) {
                    return {
                        error: "access_denied",
                        error_description: "Invalid MFA token",
                    }
                }
                if (!this.userStorage) {
                    return {
                        error: "server_error",
                        error_description: "No user storage defined",
                    }
                }
                const {user: user1} = 
                    await this.userStorage?.getUserById(key.userId);
                user = user1;
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.error(j({cerr: e, 
                    msg: "Invalid MFA token"}));
                return {
                    error: "access_denied",
                    error_description: "Invalid MFA token",
                }
            }
            if (!user) {
                return {
                    error: "access_denied",
                    error_description: "Invalid MFA token",
                }
            }
            try {
                const ofaaid = KeyStorage.decodeData(key.data)["omfaaid"];
                if (ofaaid != user.factor2) {
                    return {
                        error: "access_denied",
                        error_description: "authenticatorId not valid for user",
                    }
                }
            } catch (e) {
                return {
                    error: "server_error",
                    error_description: "Error getting data for MFA token",
                }

            }
            return {user, key};
    }
    async mfaAuthenticatorsEndpoint(mfaToken : string) : 
    Promise<{
        authenticators?: MfaAuthenticatorResponse[],
        error?: string,
        error_description?: string
    }> {

        // validate token
        const resp = await this.validateMfaToken(mfaToken);
        if (!resp.user) return resp;
        const user = resp.user;

        if (!user.factor2) {
            return {authenticators: []};
        }
        const authenticator = this.authenticators[user.factor2];
        if (!authenticator) {
            return {
                error: "server_error",
                error_description: "User has an unsupported MFA authenticator",
            }
        }

        let authenticatorResponse : MfaAuthenticatorResponse|undefined;
        if (authenticator.mfaType() == "otp") {
            authenticatorResponse = {
                id : user.factor2,
                authenticator_type: "otp",
                active: true,
            };
        } else if (authenticator.mfaType() == "oob") {
            authenticatorResponse = {
                id : user.factor2,
                authenticator_type: "oob",
                active: true,
                name: user.email??user.username,
                oob_channel: authenticator.mfaChannel(),
            };
        } else {
            return {
                error: "server_error",
                error_description: "User has an unsupported MFA authenticator",
            }

        }

        return {authenticators: [authenticatorResponse]};
    }

    async mfaChallengeEndpoint(mfaToken: string,
        clientId : string,
        clientSecret : string|undefined,
        challengeType: string,
        authenticatorId: string) :
        Promise<{
            challenge_type?: string,
            oob_code? : string,
            binding_method? : string,
            error?: string,
            error_description?: string
        }> {

        const flow = OAuthFlows.PasswordMfa;

        // get client
        const clientResponse = await this.getClient(clientId);
        if (!clientResponse.client) return clientResponse;    
        const client = clientResponse.client;

        // throw an error if client authentication is required not not present
        const clientAuthentication = 
            await this.authenticateClient(flow, client, clientSecret);
        if (clientAuthentication.error) return clientAuthentication;
    
        // validate token
        const mfa = await this.validateMfaToken(mfaToken);
        if (!mfa.user || !mfa.key) return mfa;

        if (mfa.user.factor2 != authenticatorId) {
            return {
                error: "access_denied",
                error_description: "Invalid MFA authenticator"
            }
        }

        if (challengeType != "otp" && challengeType != "oob") {
            return {
                error: "invalid_request",
                error_description: "Invalid MFA challenge type"
            };
        }

        let omfaFields : {[key:string]:any} = {};
        if (challengeType == "oob") {
            omfaFields = {
                oobCode : Hasher.randomValue(16),
            }
        }
        try {
            const authenticator = this.authenticators[mfa.user.factor2];
            if (!authenticator) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "User's authenticator has not been loaded");
            }
            const resp = await authenticator.createOneTimeSecrets(mfa.user);
            this.keyStorage.updateData(mfa.key.value,
                "omfa",
                { ...omfaFields, ...resp });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return {
                error: "server_error",
                error_description: "Unable to initiate OOB authentication",
            }
        }

        if (challengeType == "otp") {
            return {
                challenge_type: "otp"
            }

        } else /*if (challengeType == "oob")*/ {
            return {
                challenge_type: "oob",
                oob_code: omfaFields?.oobCode,
                binding_method: "prompt",
            }
        }

    }

    inferFlowFromGet(
        responseType : string, 
        scope : string[],
        codeChallenge? : string,
    ) : string|undefined {

        if (responseType == "code" && !scope.includes("openid")) {
            if (codeChallenge) return OAuthFlows.AuthorizationCodeWithPKCE;
            return OAuthFlows.AuthorizationCode;
        } else if (scope.includes("openid")) {
            if (responseType == "code") {
                if (codeChallenge) return OAuthFlows.AuthorizationCodeWithPKCE;
                return OAuthFlows.AuthorizationCode;
                /*
                // not supported yet
            } else if (responseType == "id_token") {
                return OAuthFlows.OidcAuthorizationCode;
            } else if (responseType == "id_token token" || 
                responseType == "token id_token") {
                return OAuthFlows.OidcAuthorizationCode;
            } else if (responseType == "id_token code" || 
                responseType == "code id_token") {
                return OAuthFlows.OidcAuthorizationCode;
            } else if (responseType == "token code" || 
                responseType == "code token") {
                return OAuthFlows.OidcAuthorizationCode;
            } else if (responseType == "code id_token token" || 
                responseType == "id_token code token" || 
                    responseType == "id_token token code" || 
                    responseType == "token id_token code" || 
                    responseType == "token code id_token"  || 
                    responseType == "code token id_token") {
                return OAuthFlows.OidcAuthorizationCode;
                */
            }
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
        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-otp") {
            return OAuthFlows.PasswordMfa;
        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-oob") {
            return OAuthFlows.PasswordMfa;
        }
        return undefined;

    }

    private async getAuthorizationCode(client: OAuthClient,
        redirectUri: string,
        scopes: string[] | undefined,
        state: string,
        codeChallenge?: string,
        codeChallengeMethod?: string,
        user?: User): Promise<{
            code?: string,
            state?: string,
            error?: string,
            error_description?: string
    }> {

        // if we have a challenge, check the method is valid
        if (codeChallenge) {
            if (!codeChallengeMethod) codeChallengeMethod = "S256";
            if (codeChallengeMethod != "S256" && 
                codeChallengeMethod != "plain") {
                return {
                    error: "invalid_request",
                    error_description: "Code challenge method must be S256 or plain"
                };
            }
        }

        // validate redirect uri
        const decodedUri = redirectUri; 
        OAuthAuthorizationServer.validateUri(decodedUri);
        if (this.requireRedirectUriRegistration && 
            !client.redirectUri.includes(decodedUri)) {
            return {
                error: "invalid_request",
                error_description: `The redirect uri ${redirectUri} is invalid`
            };
        }


        // create authorization code and data to store with the key
        const created = new Date();
        const expires = 
        this.authorizationCodeExpiry ? 
            new Date(created.getTime() + this.authorizationCodeExpiry*1000 + 
                this.clockTolerance*1000) : 
            undefined;
        const authzData : {[key:string]: any} = {
        }
        if (scopes) {
            authzData.scope = scopes;
        }
        if (codeChallenge) {
            authzData.challengeMethod = codeChallengeMethod;
            // we store this as a hash for security.  If S256 is used, 
            // that will be a second hash
            authzData.challenge = Hasher.hash(codeChallenge);
        }
        if (user) {
            authzData.username = user.username;
            authzData.id = user.id;
        }
        const authzDataString = JSON.stringify(authzData);

        // save the code in key storage
        let success = false;
        let authzCode = "";
        for (let i=0; i<10 && !success; ++i) {
            try {
                authzCode = Hasher.randomValue(this.authorizationCodeLength);
                this.keyStorage.saveKey(undefined,
                    AUTHZ_CODE_PREFIX + Hasher.hash(authzCode),
                    created,
                    expires,
                    authzDataString);
                success = true;
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: `Attempt nmumber${i} at creating a unique authozation code failed`}));
            }
        }
        if (!success) {
            throw new CrossauthError(ErrorCode.KeyExists,
                "Couldn't create a authorization code");
        }

        return {code: authzCode, state: state};
    }

    private async getAccessToken({
        client, 
        code, 
        clientSecret, 
        codeVerifier,  
        scopes, 
        issueRefreshToken = false, 
        user} : {
            client: OAuthClient, 
            code? : string, 
            clientSecret? : string, 
            codeVerifier? : string,  
            scopes? : string[], 
            issueRefreshToken? : boolean, 
            user? : User}) 
        : Promise<OAuthTokenResponse> {

        // validate client secret
        let passwordCorrect = true;
        try {
            // we validated this before so if authentication is required,
            // it will not be undefined
            if (client.clientSecret!=undefined) { 
                passwordCorrect = 
                    await Hasher.passwordsEqual(clientSecret??"", 
                        client.clientSecret??"");
            }
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            const message = "Couldn't validate client";
            return {error: "server_error", error_description: message};
        }
        if (!passwordCorrect) return {
            error: "access_denied",
            error_description: "Invalid client secret"
        };

        // validate authorization code
        let authzData : {
            scope? : string[],
            challenge? : string,
            challengeMethod? : string,
            userId? : number|string,
            username? : string,
            [key:string] : any, 
        } = {};

        if (code) {

            // recover scope, challenge and user from data persisted with 
            // authorization code
            let key : Key|undefined;
            try {
                key = await this.keyStorage.getKey(AUTHZ_CODE_PREFIX+Hasher.hash(code));
                authzData = KeyStorage.decodeData(key.data);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "access_denied",
                    error_description: "Invalid or expired authorization code"
                };
            }
            try {
                await this.keyStorage.deleteKey(key.value);
            } catch (e) {
                CrossauthLogger.logger.warn(j({
                    err: e,
                    msg: "Couldn't delete authorization code from storatge",
                    clientId: client?.clientId
                }));
            }
            scopes = authzData.scope;
        }
        if (user) {
            authzData.username = user.username;
        }
        
        // validate code verifier, if there is one
        if (authzData.challengeMethod && !authzData.challenge) {
            if (authzData.challengeMethod != "plain" && 
                authzData.challengeMethod != "S256") {
                return {
                    error: "access_denied",
                    error_description: "Invalid code challenge/code challenge method method for authorization code"
                };
            }
        }
        if (authzData.challenge) {
            const hashedVerifier = 
                authzData.challengeMethod == "plain" ? 
                    codeVerifier??"" : Hasher.sha256(codeVerifier??"");
            // we store the challenge in hashed form for security, 
            // so if S256 is used this will be a second hash
            if (Hasher.hash(hashedVerifier) != authzData.challenge) {
                return {
                    error: "access_denied",
                    error_description: "Code verifier is incorrect"
                };
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
            dateAccessTokenExpires = 
                new Date(now.getTime()+this.accessTokenExpiry*1000 + 
                    this.clockTolerance*1000);
        }
        if (this.resourceServers) {
            accessTokenPayload.aud = this.resourceServers;
        }

        // create access token jwt
        const accessToken : string = await new Promise((resolve, reject) => {
            jwt.sign(accessTokenPayload,
                this.secretOrPrivateKey,
                { algorithm: this.jwtAlgorithmChecked, keyid: "1" }, 
                (error: Error | null,
                encoded: string | undefined) => {
                    if (encoded) resolve(encoded);
                    else if (error) reject(error);
                    else reject(new CrossauthError(ErrorCode.Unauthorized,
                        "Couldn't create jwt"));
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
        let idToken : string|undefined = undefined;

        if (scopes && scopes.includes("openid")) {

            // create access token payload
            const idokenJti = Hasher.uuid();
            let idTokenPayload : {[key:string]: any} = {
                jti: idokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                sub: authzData.username,
                type: "id",
            };
            if ("email" in scopes && user && "email" in user) {
                idTokenPayload.email = user.email;
            }
            if ("address" in scopes && user && "address" in user) {
                idTokenPayload.address = user.address;
            }
            if ("phone" in scopes && user && "phone" in user) {
                idTokenPayload.phone = user.phone;
            }
            if ("profile" in scopes && user) {
                for (let field of ["name",
                    "family_name",
                    "given_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at"]) {
                    idTokenPayload[field] = user[field];
                }
            }
            if (user) {
                if (this.idTokenClaimsAll) {
                    idTokenPayload = {
                        ...idTokenPayload,
                        ...user
                    };
                } else {
                    for (let field in this.idTokenClaims) {
                        idTokenPayload[field] = user[this.idTokenClaims[field]];
                    }
    
                }
            }
            idTokenPayload.scope = scopes;
            if (this.accessTokenExpiry != null) {
                idTokenPayload.exp = timeCreated + this.accessTokenExpiry
            }
    
            // create access token jwt
            idToken = await new Promise((resolve, reject) => {
                jwt.sign(idTokenPayload, this.secretOrPrivateKey, {
                    algorithm: this.jwtAlgorithmChecked,
                    keyid: "1"
                    }, 
                    (error: Error | null,
                    encoded: string | undefined) => {
                        if (encoded) resolve(encoded);
                        else if (error) reject(error);
                        else reject(new CrossauthError(ErrorCode.Unauthorized,
                            "Couldn't create jwt"));
                    });
            });
    
        }

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
                refreshTokenPayload.exp = 
                    timeCreated + this.refreshTokenExpiry;
                dateRefreshTokenExpires = 
                    new Date(now.getTime()+this.refreshTokenExpiry*1000 + 
                        this.clockTolerance*1000);
            }
            if (this.resourceServers) {
                refreshTokenPayload.aud = this.resourceServers;
            }

            // create refresh token jwt
            newRefreshToken = await new Promise((resolve, reject) => {
                jwt.sign(refreshTokenPayload, this.secretOrPrivateKey, {
                    algorithm: this.jwtAlgorithmChecked,
                    keyid: "1"
                    }, 
                    (error: Error | null,
                    encoded: string | undefined) => {
                        if (encoded) resolve(encoded);
                        else if (error) reject(error);
                        else reject(new CrossauthError(ErrorCode.Unauthorized,
                            "Couldn't create jwt"));
                    });
            });

            // persist refresh token if requested
            if (this.persistRefreshToken && this.keyStorage) {
                await this.keyStorage?.saveKey(
                    undefined, // to avoid user storage dependency
                    REFRESH_TOKEN_PREFIX+Hasher.hash(refreshTokenJti),
                    now,
                    dateRefreshTokenExpires
                );
            }
        }
        
        return {
            access_token : accessToken,
            id_token: idToken,
            refresh_token : newRefreshToken,
            expires_in : this.accessTokenExpiry==null ? undefined : 
                this.accessTokenExpiry,
            token_type: "Bearer",
            scope: scopes? scopes.join(" ") : undefined,
        }
    }

    async validAuthenticationCode(token : string) : 
        Promise<{[key:string]: any}|undefined> {
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

    async validRefreshToken(token : string) : 
        Promise<{[key:string]: any}|undefined> {
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

    async validIdToken(token : string) : 
        Promise<{[key:string]: any}|undefined> {
        try {
            const decoded = await this.validateJwt(token, "id");
            return decoded;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return undefined;
        }
    }

    async validAccessToken(token : string) : 
        Promise<{[key:string]: any}|undefined> {
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

    private async validateJwt(code : string, type? : string) : 
        Promise<{[key:string]: any}> {
        return  new Promise((resolve, reject) => {
            jwt.verify(code,
                this.secretOrPublicKey,
                { clockTolerance: this.clockTolerance, complete: true }, 
                (error: Error | null,
                decoded: {[key:string]:any} | undefined) => {
                    if (decoded) {
                        if (!type || decoded.payload.type == type) {
                            resolve(decoded);
                        } else {
                            reject(new CrossauthError(ErrorCode.Unauthorized, 
                                "Invalid JWT type"));
                        }
                    } else if (error) { 
                        CrossauthLogger.logger.debug(j({err: error}));
                        reject(new CrossauthError(ErrorCode.Unauthorized, 
                            "Invalid JWT signature"));
                    } else {
                        reject(new CrossauthError(ErrorCode.Unauthorized, 
                            "Couldn't create jwt"));
                    }
                });
        });

    }

    private validateScope(scope: string): {
        error?: string,
        errorDescription?: string,
        scopes?: string[]
    } {
        let requestedScopes = [];
        try {
            requestedScopes = scope.split(" ");
        } catch (e) {
            const errorCode = "invalid_scope";
            const errorDescription = `Invalid scope ${scope}`;
            CrossauthLogger.logger.debug(j({err: CrossauthError
                .fromOAuthError(errorCode, errorDescription)}));
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
                    CrossauthLogger.logger.debug(j({err: CrossauthError
                        .fromOAuthError(errorCode, errorDescription)}));
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

    async createClient(name: string,
        redirectUri: string[],
        validFlow?: string[],
        confidential = true) : Promise<OAuthClient> {
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
            throw CrossauthError.fromOAuthError("invalid_request", 
            `Invalid redirect Uri ${uri}`);
        }
    }

    redirectUri(redirectUri : string, code : string, state : string) : string {
        const sep = redirectUri.includes("?") ? "&" : "?";
        return `${redirectUri}${sep}code=${code}&state=${state}`;
    }

    responseTypesSupported() : string[] {
        let response_types_supported = [];
        if (this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
            this.validFlows.includes(OAuthFlows.OidcAuthorizationCode)) {
            response_types_supported.push("code");
        }
        // Not supporting other OIDC flows yet
        return response_types_supported;
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
            if (grantType) grantTypes = [...grantTypes, ...grantType];
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
            authorization_endpoint: 
                new URL(authorizeEndpoint??"authorize", 
                    this.oauthIssuer).toString(),
            token_endpoint: 
                new URL(tokenEndpoint??"token",
                    this.oauthIssuer).toString(),
            token_endpoint_auth_methods_supported: ["client_secret_post"],
            jwks_uri: new URL(jwksUri??"jwks", this.oauthIssuer).toString(),
            response_types_supported: this.responseTypesSupported(),
            response_modes_supported: ["query"],
            grant_types_supported: grantTypes,
            token_endpoint_auth_signing_alg_values_supported: jwtAlgorithms,
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: jwtAlgorithms,
            claims_supported: 
                ["iss", "sub", "aud", "jti", "iat", "type", 
                    ...additionalClaims],
            request_uri_parameter_supported: true,
            require_request_uri_registration: 
                this.requireRedirectUriRegistration,
        };
    }

    jwks() : Jwks {
        let keys : JsonWebKey[] = [];
        if (this.jwtPublicKey) {
            const publicKey = 
                createPublicKey(this.jwtPublicKey).export({format: "jwk"});
            publicKey.kid = "1";
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
        if (!/^[A-Za-z0-9_-]+$/.test(response_type)) {
            error_description = "response_type is invalid";
        }
        else if (!/^[A-Za-z0-9_-]+$/.test(client_id)) {
            error_description = "client_id is invalid";
        }
        else if (scope && !/^[A-Za-z0-9_+ -]+$/.test(scope)) {
            error_description = "scope is invalid";
        }
        else if (!/^[A-Za-z0-9_-]+$/.test(state)) {
            error_description = "state is invalid";
        }
        else if (code_challenge && !/^[A-Za-z0-9_-]+$/.test(code_challenge)) {
            error_description = "code_challenge is invalid";
        }
        else if (code_challenge_method && 
            !/^[A-Za-z0-9_-]+$/.test(code_challenge_method)) {
                error_description = "code_challenge_method is invalid";
            }
        try {
            new URL(redirect_uri);
        } catch (e) {
            error_description = "redirect_uri is invalid";
        }
        if (!redirect_uri || redirect_uri.includes('#')) {
            error_description = "redirect_uri is invalid";
        }
        if (error_description) {
            return {
                error: "invalid_request",
                error_description: error_description
            };
        }
        return {};
    }
}