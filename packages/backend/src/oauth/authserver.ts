// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import jwt, { type Algorithm } from 'jsonwebtoken';
import {
    OAuthClientManager,
    type OAuthClientManagerOptions
} from './clientmanager';
import {
    KeyStorage,
    UserStorage,
    OAuthClientStorage,
    OAuthAuthorizationStorage} from '../storage';

import { Authenticator } from '../auth';
import { setParameter, ParamType } from '../utils';
import { Crypto } from '../crypto';
import type {
    OpenIdConfiguration,
    GrantType,
    Jwks,
    MfaAuthenticatorResponse } from '@crossauth/common';
import { CrossauthError, ErrorCode, UserState } from '@crossauth/common';
import type {
    OAuthClient,
    OAuthTokenResponse,
    OAuthDeviceAuthorizationResponse,
    OAuthDeviceResponse,
    Key,
    User,
} from '@crossauth/common';
import { OAuthClientBackend, OAuthClientOptions } from './client';
import { CrossauthLogger, j, KeyPrefix } from '@crossauth/common';
import { OAuthFlows } from '@crossauth/common';
import { createPublicKey, type JsonWebKey } from 'crypto'
import fs from 'node:fs';
//import fs, { access } from 'node:fs';

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

/**
 * If using an upstream authz server, this is the signature for the function
 * you need to merge the upstream token with your own custom fields
 */
export type TokenMergeFn = 
    (accessPayload : string|{[key:string]:any}, 
        idPayload : {[key:string]:any}|undefined, 
        userStorage? : UserStorage) => 
            Promise<{authorized: boolean,
                error? : string, 
                error_description? : string, 
                access_payload?: {[key:string]:any}, 
                id_payload?: {[key:string]:any}}>;

/**
 * Options for declaring an upstream authz server
 */
export interface UpstreamClientOptions {
    options : OAuthClientOptions,
    tokenMergeFn : TokenMergeFn,
    authServerBaseUrl : string,
    scopes?: string[],
    sessionDataName? : string,
    accessTokenIsJwt : boolean
}

/**
 * Options for {@link OAuthAuthorizationServerOptions}.
 */
export interface OAuthAuthorizationServerOptions extends OAuthClientManagerOptions {

    /** JWT issuer, eg https://yoursite.com.  Required (no default) */
    oauthIssuer? : string,

    /** JWT issuer, eg https://yoursite.com.  Required (no default) */
    audience? : string,

    /** If true, only redirect Uri's registered for the client will be 
     * accepted */
    requireRedirectUriRegistration?: boolean,

    /** If true, the authorization code flow will require either a client 
     * secret or PKCE challenger/verifier.  Default true */
    requireClientSecretOrChallenge?: boolean,

    /** Authorization code length, before base64url-encoding.  Default 32 */
    codeLength? : number,

    /** The algorithm to sign JWTs with.  Default `RS256` */
    jwtAlgorithm? : string,

    /** Type of key in jwtPublicKey, jwtPublicKeyFile, etc, eg RS256*/
    jwtKeyType? : string,

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

    /**
     * The kid to give the jwt signing key.  Default "1".
     */
    jwtKid? : string,

    /** Whether to persist access tokens in key storage.  Default false */
    persistAccessToken? : boolean,

    /** Whether to issue a refresh token.  Default false */
    issueRefreshToken? : boolean,

    /** If true, access token will contain no data, just a random string.  
     * This will turn persistAccessToken on.  Default false. */
    opaqueAccessToken? : boolean,

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

    /** Expiry for user codes codes in seconds.   Defult 5 minutes */
    userCodeExpiry? : number,

    /** Milliseconds to wait after each failed code attempt
     * Default 1500.  A 1500ms throttle and 8 character user codes gives 
     * a brute force a 2^-32 chance of success at brute forcing.
     */
    userCodeThrottle? : number,

    /** For device code flow, tell client to use a poll interval of this many seconds.
     * Default 5.
     */
    deviceCodePollInterval? : number,

    /** Length for device codes (before base64-encoding).  Default 16
     */
    deviceCodeLength? : number,

    /** 
     * Length for user codes codes in base 32.  Default 8.
     */
    userCodeLength? : number,

    /** 
     * Put a dash after this number of characters in user codes.
     * null means no dashes.  Dashes are ignored during validation.
     * Default 4
     */
    userCodeDashEvery? : number,

    /**
     * URI to tell user to go to to enter user code in device code flow.
     * 
     * No default - required if using the device flow.
     */
    deviceCodeVerificationUri? : string,

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
    validScopes? : string[],

    /** Flows to support.  A comma-separated list from {@link @crossauth/common!OAuthFlows}.  
     * If [`all`], there must be none other in the list.  Default [`all`] */
    validFlows? : string[],

    /** Required if emptyScopeIsValid is false */
    authStorage? : OAuthAuthorizationStorage,

    /** Required if activating the password flow */
    userStorage? : UserStorage;

    /** A JSON string of customs fields per scope to put in id token.
     * `{"scope": "all"}` or `{"scope": {"idtokenfield" : "userfield"}}`.
     * If `scope` is `all` then it applies to all scopes
     */
    idTokenClaims? : {[key:string] : string|string[]|{[key:string]:string}};

    /** A JSON string of customs fields per scope to put in access token.
     * `{"scope": "all"}` or `{"scope": {"idtokenfield" : "userfield"}}`.
     * If `scope` is `all` then it applies to all scopes
     */
    accessTokenClaims? : {[key:string] : string|string[]|{[key:string]:string}};

    /**
     * The 2FA factors that are allowed for the Password MFA flow.
     */
    allowedFactor2? : string[],

    upstreamClient?: UpstreamClientOptions;
}

/**
 * OAuth authorization server.
 * 
 * This provides framework-independent functionality for the
 * authorization server.  It supports the Authorization Code Flow
 * with and without PKCE, the Password Flow. Refresh Token Flow,
 * Client Credentials Flow and the Password MFA flow.  For the later, see
 * {@link https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors}.
 * 
 * It also supports the OpenID Connect Authorization Code Flow, with and 
 * without PKCE.
 */
export class OAuthAuthorizationServer {

    private clientStorage : OAuthClientStorage;
    private keyStorage : KeyStorage;
    readonly userStorage? : UserStorage;
    private authenticators : {[key:string] : Authenticator} = {};
    private authStorage? : OAuthAuthorizationStorage;

    /** For validating redirect URIs. */
    clientManager : OAuthClientManager;

    private oauthIssuer : string = "";
    private audience : string|null = null;
    readonly requireRedirectUriRegistration = true;
    private requireClientSecretOrChallenge = true;
    private jwtAlgorithm = "RS256";
    private jwtAlgorithmChecked : Algorithm = "RS256";
    readonly codeLength = 32;
    private jwtKeyType = "";
    private jwtSecretKey = "";
    private jwtPublicKey = "";
    private jwtPrivateKey = "";
    private jwtSecretKeyFile = "";
    private jwtPublicKeyFile = "";
    private jwtPrivateKeyFile = "";
    private jwtKid = "1";
    private secretOrPrivateKey = "";
    private secretOrPublicKey = "";
    private persistAccessToken = false;
    private issueRefreshToken = false;
    private opaqueAccessToken = false;
    private accessTokenExpiry : number|null = 60*60;
    private refreshTokenExpiry : number|null = 60*60;
    private rollingRefreshToken : boolean = true;
    private authorizationCodeExpiry : number|null = 60*5;
    private mfaTokenExpiry : number|null = 60*5;
    private clockTolerance : number = 10;
    private emptyScopeIsValid : boolean = true;
    private validateScopes : boolean = false;
    private validScopes : string[] = [];
    private idTokenClaims : {[key:string] : any} = {};
    private accessTokenClaims : {[key:string] : any} = {};

    ///// Upstream AUth server config

    /**
     * The OAuth client to the upstream authz server if configured
     */
    upstreamClient? : OAuthClientBackend;

    /**
     * The OAuth client to the upstream authz server if configured
     */
    upstreamClientOptions? : UpstreamClientOptions;

    // device code
    private userCodeExpiry = 60*5;
    readonly userCodeThrottle = 1500;
    private deviceCodePollInterval = 5;
    private userCodeLength = 8;
    private deviceCodeLength = 16;
    private userCodeDashEvery : number|null = 4;
    private deviceCodeVerificationUri : string = "";
    private authServerBaseUrl = "";

    /** Set from options.  See {@link OAuthAuthorizationServerOptions.validFlows} */
    validFlows : string[] = ["all"];

    /** Set from options.  See {@link OAuthAuthorizationServerOptions.allowedFactor2} */
    allowedFactor2 : string[] = [];

    /**
     * Constructor
     * 
     * @param clientStorage where OAuth clients are stored
     * @param keyStorage  where session IDs are stored
     * @param authenticators set of authenticators for validating users
     *        with Password and Password MFA flows
     *        (all factor 1 authenticators users may have plus factor 2
     *         authenticators for the Password MFA flow)
     * @param options See {@link OAuthAuthorizationServerOptions }
     */
    constructor(clientStorage: OAuthClientStorage,
        keyStorage: KeyStorage,
        authenticators? : {[key:string] : Authenticator},
        options: OAuthAuthorizationServerOptions = {}) {
        this.clientStorage = clientStorage;
        this.keyStorage = keyStorage;
        this.userStorage = options.userStorage;
        this.authStorage = options.authStorage;
        if (authenticators) {
            this.authenticators = authenticators;
        }
        this.clientManager = new OAuthClientManager({clientStorage, ...options});

        setParameter("authServerBaseUrl", ParamType.String, this, options, "AUTH_SERVER_BASE_URL", true);
        setParameter("oauthIssuer", ParamType.String, this, options, "OAUTH_ISSUER");
        if (!this.oauthIssuer) 
            this.oauthIssuer = this.authServerBaseUrl;
        setParameter("audience", ParamType.String, this, options, "OAUTH_AUDIENCE");
        setParameter("oauthPbkdf2Iterations", ParamType.String, this, options, "OAUTH_PBKDF2_ITERATIONS");
        setParameter("requireClientSecretOrChallenge", ParamType.Boolean, this, options, "OAUTH_REQUIRE_CLIENT_SECRET_OR_CHALLENGE");
        setParameter("jwtAlgorithm", ParamType.String, this, options, "JWT_ALGORITHM");
        setParameter("codeLength", ParamType.Number, this, options, "OAUTH_CODE_LENGTH");
        setParameter("jwtKeyType", ParamType.String, this, options, "JWT_KEY_TYPE");
        setParameter("jwtSecretKeyFile", ParamType.String, this, options, "JWT_SECRET_KEY_FILE");
        setParameter("jwtPublicKeyFile", ParamType.String, this, options, "JWT_PUBLIC_KEY_FILE");
        setParameter("jwtPrivateKeyFile", ParamType.String, this, options, "JWT_PRIVATE_KEY_FILE");
        setParameter("jwtSecretKey", ParamType.String, this, options, "JWT_SECRET_KEY");
        setParameter("jwtPublicKey", ParamType.String, this, options, "JWT_PUBLIC_KEY");
        setParameter("jwtPrivateKey", ParamType.String, this, options, "JWT_PRIVATE_KEY");
        setParameter("jwtKid", ParamType.String, this, options, "JWT_KID");
        setParameter("persistAccessToken", ParamType.String, this, options, "OAUTH_PERSIST_ACCESS_TOKEN");
        setParameter("issueRefreshToken", ParamType.String, this, options, "OAUTH_ISSUE_REFRESH_TOKEN");
        setParameter("opaqueAccessToken", ParamType.String, this, options, "OAUTH_OPAQUE_ACCESS_TOKEN");
        setParameter("accessTokenExpiry", ParamType.Number, this, options, "OAUTH_ACCESS_TOKEN_EXPIRY");
        setParameter("refreshTokenExpiry", ParamType.Number, this, options, "OAUTH_REFRESH_TOKEN_EXPIRY");
        setParameter("rollingRefreshToken", ParamType.Boolean, this, options, "OAUTH_ROLLING_REFRESH_TOKEN");
        setParameter("authorizationCodeExpiry", ParamType.Number, this, options, "OAUTH_AUTHORIZATION_CODE_EXPIRY");
        setParameter("mfaTokenExpiry", ParamType.Number, this, options, "OAUTH_MFA_TOKEN_EXPIRY");
        setParameter("clockTolerance", ParamType.Number, this, options, "OAUTH_CLOCK_TOLERANCE");
        setParameter("validateScopes", ParamType.Boolean, this, options, "OAUTH_VALIDATE_SCOPES");
        setParameter("emptyScopeIsValid", ParamType.Boolean, this, options, "OAUTH_EMPTY_SCOPE_VALID");
        setParameter("validScopes", ParamType.JsonArray, this, options, "OAUTH_VALID_SCOPES");
        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_validFlows");
        setParameter("idTokenClaims", ParamType.Json, this, options, "OAUTH_ID_TOKEN_CLAIMS");
        setParameter("accessTokenClaims", ParamType.Json, this, options, "OAUTH_ACCESS_TOKEN_CLAIMS");
        setParameter("allowedFactor2", ParamType.JsonArray, this, options, "ALLOWED_FACTOR2");

        // device code
        setParameter("userCodeExpiry", ParamType.Number, this, options, "DEVICECODE_USERCODE_EXPIRY");
        setParameter("userCodeThrottle", ParamType.Number, this, options, "DEVICECODE_USERCODE_THROTTLE");
        setParameter("deviceCodePollInterval", ParamType.Number, this, options, "DEVICECODE_POLL_INTERVAL");
        setParameter("deviceCodeLength", ParamType.Number, this, options, "DEVICECODE_LENGTH");
        setParameter("userCodeLength", ParamType.Number, this, options, "DEVICECODE_USERCODE_LENGTH");
        let tmp : {userCodeDashEvery? : string} = {};
        setParameter("userCodeDashEvery", ParamType.String, tmp, options, "DEVICECODE_USERCODE_DASH_EVERY");
        if (tmp.userCodeDashEvery) {
            if (tmp.userCodeDashEvery == "" || tmp.userCodeDashEvery.toLowerCase() == "null") this.userCodeDashEvery = null;
            else {
                try {
                    this.userCodeDashEvery = Number(tmp.userCodeDashEvery)
                } catch (e) {
                    throw new CrossauthError(ErrorCode.Configuration,
                        "userCodeDashEvery must be a number or null")
                }
            }
        }
        setParameter("deviceCodeVerificationUri", ParamType.String, this, options, "DEVICECODE_VERIFICATION_URI");

        ///// upstream client for forwarding authorization code flow to
        if (options.upstreamClient) {
            this.upstreamClientOptions = options.upstreamClient;
            this.upstreamClient = new OAuthClientBackend(options.upstreamClient.authServerBaseUrl, options.upstreamClient.options);
            if (!options.upstreamClient.options.redirect_uri) {
                throw new CrossauthError(ErrorCode.Configuration, "Must define redirect_uri in upstreamClient options")
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
        if ((this.jwtPublicKey || this.jwtPrivateKey) && !this.jwtKeyType) {
            throw new CrossauthError(ErrorCode.Configuration,
                "If setting jwtPublicKey or jwtPrivate key, must also set jwtKeyType");
        }

        if (this.opaqueAccessToken) this.persistAccessToken = true;

        if ((this.validFlows.includes(OAuthFlows.Password) || 
             this.validFlows.includes(OAuthFlows.PasswordMfa) ) 
             && (!this.userStorage || Object.keys(this.authenticators).length == 0)) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "If password flow or password MFA flow is enabled, userStorage and authenticators must be provided");
        }

        if ((this.issueRefreshToken || this.persistAccessToken) &&
            !this.keyStorage) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "Must have key storage if persisting access tokens or issuing refresh tokens");
            }
    }

    /**
     * The the OAuth2 authorize endpoint.  All parameters are expected to be
     * strings and have be URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     * @param options object whose values correspond to the OAuth `authorize`
     *        endpoint, plus `user` if one is logged in at the authorization
     *        server.
     * @returns Values that correspond to the OAuth `authorize` endpoint
     *          JSON response. 
     */
    async authorizeGetEndpoint({
            responseType, 
            client_id, 
            redirect_uri, 
            scope, 
            state,
            codeChallenge,
            codeChallengeMethod,
            user,
        } : {
            responseType : string, 
            client_id : string, 
            redirect_uri : string, 
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
            client = await this.clientStorage.getClientById(client_id);
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
            = await this.validateAndPersistScope(client_id, scope, user);
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
        if (!client.valid_flow.includes(flow)) {
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
                redirect_uri,
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

    /**
     * Returns whether or not the user has authorized all the passed scopes
     * for the given client.
     * 
     * @param client_id the client ID
     * @param user the user logged in at the authorization server.
     * @param requestedScopes the scopes that have been requested
     * @returns true or false.
     */
    async hasAllScopes(client_id: string,
        user: User | undefined,
        requestedScopes: (string | null)[]) : Promise<boolean> {
        if (!this.authStorage) return false;
        const existingScopes = 
            await this.authStorage.getAuthorizations(client_id, user?.id);
        const existingRequestedScopes = 
            requestedScopes.filter((scope) => existingScopes.includes(scope));
        return existingRequestedScopes.length == requestedScopes.length;
    }

    async validateAndPersistScope(client_id: string,
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
                    = await this.authStorage.getAuthorizations(client_id,
                        user?.id);
                const updatedScopes = 
                    [...new Set([...existingScopes, ...newScopes])];
                CrossauthLogger.logger.debug(j({
                    msg: "Updating authorizations for " + client_id + " to " + updatedScopes}));
                await this.authStorage.updateAuthorizations(client_id,
                    user?.id ?? null,
                    updatedScopes);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return {
                    error: "server_error",
                    error_description: "Couldn't save scope"
                };
            }
        } else if (scope) {
            return {
                error: "server_error",
                error_description: "Must provide auth storage in order to use scopes"
            };

        }
        return {scopes: scopes};
    }

    private async authenticateClient(flow: string,
        client: OAuthClient,
        client_secret?: string) :
        Promise<{error?: string, error_description? : string}>
    {
        let authenticateClient = false;
        switch (flow) {
            case OAuthFlows.AuthorizationCode:
            case OAuthFlows.AuthorizationCodeWithPKCE:
                authenticateClient = (client.confidential==true || 
                    client.client_secret != undefined || 
                    client_secret != undefined);
                break;
            case OAuthFlows.ClientCredentials:
                authenticateClient = true;
                break;
            case OAuthFlows.Password:
            case OAuthFlows.PasswordMfa:
                authenticateClient = (client.confidential==true || 
                    client.client_secret != undefined || 
                    client_secret != undefined);
                break;
            case OAuthFlows.RefreshToken:
                authenticateClient = (client.confidential==true || 
                    client.client_secret != undefined || 
                    client_secret != undefined);
                break;
            case OAuthFlows.DeviceCode:
                authenticateClient = (client.confidential==true || 
                    client.client_secret != undefined || 
                    client_secret != undefined);
                break;
        }
        if (authenticateClient && (client.client_secret==undefined || 
            client_secret==undefined)) {
            return {
                error: "access_denied",
                error_description: "Client secret is required for this client",
            }
        }
        if (authenticateClient && (!client_secret || !client.client_secret)) {
            return {
                error: "access_denied",
                error_description: "Client is confidential but either secret not passed or is missing in database",
            }
        }
        if (authenticateClient) {
            const passwordCorrect = 
                await Crypto.passwordsEqual(client_secret??"", 
                    client.client_secret??"");
            if (!passwordCorrect) {
                return {
                    error: "access_denied",
                    error_description: "Incorrect client secret",
                }

            }
        }
        return {};

    }

    /**
     * Returns the matching client or an error if it does nto exist
     * @param client_id 
     * @returns the client_id, or an error or `access_denied`.
     */
    async getClientById(client_id : string) : 
        Promise<{
            client?: OAuthClient,
            error?: string,
            error_description?: string
    }> {
        let client : OAuthClient;
        try {
            client = await this.clientStorage.getClientById(client_id);
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
     * strings and have been URL-decoded.
     * 
     * For arguments and return parameters, see OAuth2 documentation.
     * @param options these arguments correspond to the OAuth `token`
     *        endpoint inputs.
     * @return the return object's fields correspond to the OAuth `token`
     *         endpoint JSON output.
     */
    async tokenEndpoint({
        grantType, 
        client_id, 
        scope, 
        code,
        client_secret,
        codeVerifier,
        refreshToken,
        username,
        password,
        mfaToken,
        oobCode,
        bindingCode,
        otp,
        deviceCode,
    } : {
        grantType : string, 
        client_id : string, 
        scope? : string, 
        code? : string,
        client_secret? : string,
        codeVerifier? : string,
        refreshToken? : string,
        username? : string,
        password? : string,
        mfaToken? : string,
        oobCode? : string,
        bindingCode?: string,
        otp? : string,
        deviceCode? : string}) 
    : Promise<OAuthTokenResponse> {


        const flow = this.inferFlowFromPost(grantType, codeVerifier);
        if (!flow) return {
            error: "server_error",
            error_description: "Unable to determine OAuth flow type",

        }

        // get client
        const clientResponse = await this.getClientById(client_id);
        if (!clientResponse.client) return clientResponse;    
        const client = clientResponse.client;

        // throw an error if client authentication is required not not present
        const clientAuthentication = 
            await this.authenticateClient(flow, client, client_secret);
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
        if (client && !client.valid_flow.includes(flow)) {
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
                (client && client.client_secret && !client_secret) && 
                !codeVerifier) {
                return {
                    error : "access_denied",
                    error_description: "Must provide either a client secret or use PKCE",
                };
            }

            if (client && client.client_secret && !client_secret) {
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

            return await this.makeAccessToken({
                client,
                code,
                client_secret,
                codeVerifier,
                issueRefreshToken: createRefreshToken
            });

        } else if (grantType == "refresh_token") {

            // pass onto upstream authz server if one is defined
            // handle the case where we have an upstream authz server
            // either throw redirect or return error
            if (this.upstreamClient && this.upstreamClientOptions) {
                if (!refreshToken) {
                    return {
                        error: "invalid_request",
                        error_description: "If executing the refresh token flow, must  provide a refresh token"
                    }
                }
                let upstream_resp = await this.upstreamClient.refreshTokenFlow(refreshToken);
                if (!upstream_resp.access_token) {
                    return {
                        error: "access_denied",
                        error_description: "Didn't receive an access token",
                    }
                }
                let accessTokenOrPayload : {[key:string]:any}|string|undefined = upstream_resp.access_token;
                if (this.upstreamClientOptions.accessTokenIsJwt) {
                    accessTokenOrPayload = await this.upstreamClient.validateAccessToken(upstream_resp.access_token, false);
                    if (!accessTokenOrPayload) {
                        return {
                            error: "access_denied",
                            error_description: "Couldn't decode access token"
                        };
                    }
                }
                const mergeResponse = await this.upstreamClientOptions.tokenMergeFn(accessTokenOrPayload, upstream_resp.id_payload, this.userStorage);    
                if (mergeResponse.authorized) {
                    const ret = await this.createTokensFromPayload(client_id,
                        mergeResponse.access_payload, mergeResponse.id_payload
                    );
                    upstream_resp.access_token = ret.access_token;
                    upstream_resp.id_token = ret.id_token;
                    upstream_resp.id_payload = ret.id_payload;
                    return upstream_resp;
                } else {
                    CrossauthLogger.logger.warn(j({msg: mergeResponse.error_description}));
                    return {
                        error: mergeResponse.error,
                        error_description: mergeResponse.error_description
                    };
                }                            
    }

            const refreshData = await this.getRefreshTokenData(refreshToken);
            if (!refreshToken || !refreshData || !this.userStorage) {
                return {
                    error: "access_denied",
                    error_description: "Refresh token is invalid",
                }
            }
            let user : User|undefined;
            if (refreshData.username) {
                try {
                    const {user: user1} = await this.userStorage?.getUserByUsername(refreshData.username);
                    user = user1;
                } catch (e) {
                    CrossauthLogger.logger.error(j({
                        err: e,
                        msg: "Couldn't get user for refresh token.  Doesn't exist?",
                        username: refreshData.username
                    }))
                    return {
                        error: "access_denied",
                        error_description: "Refresh token is invalid",
                    }
                }
            }
            try {
                const hash = KeyPrefix.refreshToken + Crypto.hash(refreshToken);
                await this.keyStorage.deleteKey(hash);   
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.warn(j({msg: "Cannot delete refresh token", cerr: ce}))
            }

            return await this.makeAccessToken({
                client,
                client_secret,
                codeVerifier,
                issueRefreshToken: createRefreshToken,
                scopes: refreshData.scope,
                user: user
            });

        } else if (grantType == "client_credentials") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(client_id, scope, undefined);
            if (scopeError) {
                return {
                            error: scopeError,
                            error_description: scopeErrorDesciption
                };
            }
    
            return await this.makeAccessToken({
                client,
                client_secret,
                codeVerifier,
                scopes,
                issueRefreshToken: createRefreshToken
            });

        } else if (grantType == "password") {
    
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
            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(client_id, scope, user);
            if (scopeError) {
                return {
                    error: scopeError,
                    error_description: scopeErrorDesciption
                };
            }
            if (user.factor2) {
                if (this.allowedFactor2.length > 0 && 
                    (user.state == UserState.factor2ResetNeeded || 
                    !this.allowedFactor2.includes(user.factor2?user.factor2:"none"))) {
                        return {
                            error: "access_denied",
                            error_description: "2FA method not allowed or needs to be reconfigured"
                        }
                    } else {
                        return await this.createMfaRequest(user);
                    }
            }
            return await this.makeAccessToken({
                client, 
                client_secret, 
                codeVerifier, 
                scopes, 
                issueRefreshToken: createRefreshToken, 
                user});

        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-otp") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(client_id, scope, undefined);
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
            const mfaKey = KeyPrefix.mfaToken + Crypto.hash(mfaToken);

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
                await this.keyStorage.deleteKey(mfaKey);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.warn(j({
                    cerr: e,
                    msg: "Couldn't delete mfa token",
                    hashedMfaToken: mfa.key.value
                }))
            }
    
            return await this.makeAccessToken({
                client, 
                client_secret, 
                codeVerifier, 
                scopes,
                issueRefreshToken: createRefreshToken, 
                user: mfa.user});

        } else if (grantType == "http://auth0.com/oauth/grant-type/mfa-oob") {

            // validate scopes
            const { scopes,
                error: scopeError,
                error_description: scopeErrorDesciption } = 
                await this.validateAndPersistScope(client_id, scope, undefined);
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
                    error_description: "OOB code or binding code not provided"
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
                await this.keyStorage.deleteKey(mfa.key.value);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.warn(j({
                    cerr: e,
                    msg: "Couldn't delete mfa token",
                    hashedMfaToken: mfa.key.value
                }))
            }

            return await this.makeAccessToken({
                client, 
                client_secret, 
                codeVerifier, 
                scopes,
                issueRefreshToken: createRefreshToken, 
                user: mfa.user});

        } else if (grantType == "urn:ietf:params:oauth:grant-type:device_code") {

            // validate device code
            if (!deviceCode) {
                return {
                    error: "invalid_request",
                    error_description: "No device code given"
                };
            }
            let deviceCodeKey : Key;
            try {
                deviceCodeKey = await this.keyStorage.getKey(KeyPrefix.deviceCode + deviceCode);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({msg: "Couldn't get device code", cerr: ce}));
                return {
                    error: "accerss_denied",
                    error_description: "Invalid device code"
                };
            }

            try {
                const data = JSON.parse(deviceCodeKey.data ?? "{}");
                const now = (new Date()).getTime();
                if (deviceCodeKey.expires && now > deviceCodeKey.expires.getTime()) {
                    await this.deleteDeviceCode(deviceCode);
                    return {
                        error: "expired_token",
                        error_description: "Code has expired",
                    }
                }
                else if (!(data.ok == true)) {
                    return {
                        error: "authorization_pending",
                        error_description: "Waiting for user code to be entered",
                    }
                } else {
                    let scopes = data.scope ? data.scope.split(" ") : undefined;
                    let userResponse = data.userid ? await this.userStorage?.getUserById(data.userid) : undefined;
                    await this.deleteDeviceCode(deviceCode);
                    return await this.makeAccessToken({
                        client,
                        client_secret,
                        codeVerifier,
                        scopes,
                        issueRefreshToken: createRefreshToken,
                        user: userResponse?.user,
                    });
                }
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({msg: "Couldn't get device code", cerr: ce}));
                await this.deleteDeviceCode(deviceCode);
                return {
                    error: "accerss_denied",
                    error_description: "Invalid device code"
                };
            }

        
    
        } else {

            return {
                error : "invalid_request",
                error_description: `Invalid grant_type ${grantType}`,
            };

        }
    }

    private async deleteDeviceCode(deviceCode : string) {
        try {
            await this.keyStorage.deleteKey(KeyPrefix.deviceCode + deviceCode);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Couldn't delete device code", cerr: ce}));
        }
    }

    private async deleteUserCode(userCode : string) {
        try {
            await this.keyStorage.deleteKey(KeyPrefix.userCode + userCode);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Couldn't delete user code", cerr: ce}));
        }
    }

    /**
     * The the OAuth2 device authorization endpoint for starting the
     * device flow.  All parameters are expected to be
     * strings and have been URL-decoded.
     * 
     * For arguments and return parameters, see RFC 8628.
     * @param options these arguments correspond to the device authorization
     *        endpoint in RFC 8628 section 3.1.
     * @return the return object's fields correspond to the OAuth `token`
     *         endpoint JSON output.
     */
    async deviceAuthorizationEndpoint({
        client_id, 
        scope, 
        client_secret,
    } : {
        client_id : string, 
        scope? : string, 
        client_secret? : string}) 
    : Promise<OAuthDeviceAuthorizationResponse> {

        // validate verification URI
        if (this.deviceCodeVerificationUri == "") {
            return {
                error: "invalid_request",
                error_description: "Must provide deviceCodeVerificationUri if using the device code flow"
            }
        }
        try {
            new URL(this.deviceCodeVerificationUri)
        } catch (e) {
            //throw new CrossauthError(ErrorCode.Configuration, "Invalid deviceCodeVerificationUri " + this.deviceCodeVerificationUri);
            return {
                error: "invalid_request",
                error_description: "Invalid deviceCodeVerificationUri"
            }
        }

        const flow = OAuthFlows.DeviceCode;

        // get client
        const clientResponse = await this.getClientById(client_id);
        if (!clientResponse.client) return clientResponse;    
        const client = clientResponse.client;

        // throw an error if client authentication is required not not present
        const clientAuthentication = 
            await this.authenticateClient(flow, client, client_secret);
        if (clientAuthentication.error) return clientAuthentication;

        // validate flow type
        if (!(this.validFlows.includes(flow))) {
            return {
                error: "access_denied",
                error_description: "Unsupported flow type " + flow,
            };    
        }

        // validate scopes 
        if (scope) {
            const {error: scopeError, errorDescription: scopeErrorDesciption} = 
                this.validateScope(scope);
            if (scopeError) return {error: scopeError, 
                error_description: scopeErrorDesciption};        
        }

        // create a device code
        let deviceCode = undefined; 
        let ok = false;
        const created = new Date();
        const expirySecs = this.userCodeExpiry;
        const expires = 
            new Date(created.getTime() + this.userCodeExpiry*1000 + 
                    this.clockTolerance*1000);
        for (let i=0; i<10 && !ok; ++i) {
            try {
                deviceCode = Crypto.randomValue(this.deviceCodeLength);
                await this.keyStorage.saveKey(undefined,
                    KeyPrefix.deviceCode + deviceCode,
                    created,
                    expires,
                    JSON.stringify({scope: scope, client_id: client_id}));
                ok = true;
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: `Attempt number${i} at creating a unique authozation code failed`}));
            }
        }
        if (!ok || !deviceCode) {
            return {
                error: "server_error",
                error_description: "Couldn't create device code",
            };
        }

        // create a user code
        let userCode = undefined; 
        ok = false;
        for (let i=0; i<10 && !ok; ++i) {
            try {
                userCode = Crypto.randomBase32(this.userCodeLength);
                await this.keyStorage.saveKey(undefined,
                    KeyPrefix.userCode + userCode,
                    created,
                    expires,
                    JSON.stringify({deviceCode: deviceCode}));
                ok = true;
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: `Attempt number${i} at creating a unique authozation code failed`}));
            }
        }
        if (!ok || !userCode) {
            await this.deleteDeviceCode(deviceCode);
            return {
                error: "server_error",
                error_description: "Couldn't create device code",
            };
        }

        if (userCode && this.userCodeDashEvery) {
            const re = new RegExp(String.raw`(.{1,${this.userCodeDashEvery}})`, "g");
            userCode = userCode.match(re)?.join("-");
        }
        return {
            device_code: deviceCode,
            user_code: userCode,
            verification_uri: this.deviceCodeVerificationUri,
            verification_uri_complete: this.deviceCodeVerificationUri + "?user_code=" + userCode,
            expires_in: expirySecs,
            interval: this.deviceCodePollInterval,
        }

    }

    /**
     * The the OAuth2 device authorization endpoint for starting the
     * device flow.  All parameters are expected to be
     * strings and have been URL-decoded.
     * 
     * For arguments and return parameters, see RFC 8628.
     * @param options these arguments correspond to the device authorization
     *        endpoint in RFC 8628 section 3.1.
     * @return the return object's fields correspond to the OAuth `token`
     *         endpoint JSON output.
     */
    async deviceEndpoint({
        userCode,
        user,
    } : {
        userCode : string,
        user : User}) 
    : Promise<OAuthDeviceResponse> {
    
        // validate user code 
        userCode = userCode.replace(/[ -]*/g, '');
        let userCodeKey : Key|undefined = undefined;
        let userCodeData : {[key:string]:any} = {};
        try {
            userCodeKey = await this.keyStorage.getKey(KeyPrefix.userCode + userCode);
            userCodeData = JSON.parse(userCodeKey?.data ?? "{}");
        } catch (e) {

            // user code is invalid - tell user
            return {
                ok: false,
                error: "access_denied",
                error_description: "Invalid user code",
            }
        }

        if (!userCodeData.deviceCode) {
            // there is no device code in the user code data - delete
            CrossauthLogger.logger.error(j({msg: "No device code for user code", userCodeHash: Crypto.hash(userCode)}));
            await this.deleteUserCode(userCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "No device code for user code",
            }
        }

        let deviceCodeKey : Key;
        try {
            deviceCodeKey = await this.keyStorage.getKey(KeyPrefix.deviceCode + userCodeData.deviceCode);
        } catch (e) {
            // there is an invalid device code in the user code data - delete
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Invalid device code for user code", 
                userCodeHash: Crypto.hash(userCode), 
                deviceCodeHash: Crypto.hash(userCodeData.deviceCode), 
                cerr: ce}));
            await this.deleteUserCode(userCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "Invalid device code user code",
            }
        }
        let scope : string|undefined = undefined;
        let client_id : string|undefined = undefined;
        try {
            if (!deviceCodeKey.data) throw new CrossauthError(ErrorCode.UnknownError);
            const data = JSON.parse(deviceCodeKey.data);
            scope = data.scope;
            client_id = data.client_id;
            if (!client_id) throw new CrossauthError(ErrorCode.UnknownError)
        } catch (e) {
            await this.deleteUserCode(userCode);
            await this.deleteDeviceCode(userCodeData.deviceCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "Unexpected or incomplete data in device code key",
            }
        }
            
        // check if the user code has expired.
        const now = new Date().getTime(); 
        if (now > userCodeData.expires?.getTime()) {

            // delete the user code
            await this.deleteUserCode(userCode);
            // We don't delete the device key as the RFC says the polling
            // must return token_expired.  We let the polling delete it instead.
            // we also don't log - expect to caller to log with the IP address
            return {
                ok: false,
                error: "expired_token",
                error_description: "User code has expired",
                client_id: client_id,
            };

        }

        // check if the user code was already used.  This gets deleted after
        // the token endpoint returns ok
        if (userCodeData.ok == true) {
            return {
                ok: false,
                error: "access_denied",
                error_description: "User code has already been used",
                client_id: client_id,
            };
        }

        // check scopes - if they are not authorized, don't set to ok
        // but tell the caller to request authority
        let hasAllScopes = false;
        CrossauthLogger.logger.debug(j({
            msg: `Checking scopes have been authorized`,
            scope: scope }))
        if (scope) {
            hasAllScopes = await this.hasAllScopes(client_id,
                user,
                scope.split(" "));

        } else {
            hasAllScopes = await this.hasAllScopes(client_id,
                user,
                [null]);
        }

        if (!hasAllScopes) {
            try {
                if (user?.id) await this.keyStorage.updateData(KeyPrefix.deviceCode + userCodeData.deviceCode, "userid", user.id);
            } catch (e) {
                // error updating device code data, so delete both device code and user code
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.warn(j({msg: "Couldn't update user id on user code entry - deleting", cerr: ce}));
                await this.deleteUserCode(userCode);
                await this.deleteDeviceCode(userCodeData.deviceCode);
                return {
                    ok: false,
                    error: "access_denied",
                    error_description: "Invalid user code",
                    client_id: client_id
                };
            }
            return {
                ok: true,
                scope,
                client_id: client_id,
                scopeAuthorizationNeeded: true,
            }
    
        }

        // ok - store this in the user code, along with the userid
        try {
            if (user?.id) await this.keyStorage.updateData(KeyPrefix.deviceCode + userCodeData.deviceCode, "userid", user.id);
            await this.keyStorage.updateData(KeyPrefix.deviceCode + userCodeData.deviceCode, "ok", true);
        } catch (e) {
            // error updating device code data, so delete both device code and user code
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.warn(j({msg: "Couldn't update status on user code entry - deleting", cerr: ce}));
            await this.deleteUserCode(userCode);
            await this.deleteDeviceCode(userCodeData.deviceCode);
            return {
                ok: false,
                error: "access_denied",
                error_description: "Invalid user code",
                client_id: client_id        };
        }

        // we no longer need the user code, so delete it
        await this.deleteUserCode(userCode);
        
        // tell the caller the user code enty was successful
        return {
            ok: true,
            scope,
            client_id: client_id
        }

    }
    

                
    async authorizeDeviceFlowScopes(userCode : string) : Promise<OAuthDeviceResponse>{
        // validate user code 
        userCode = userCode.replace(/[ -]*/g, '');
        let userCodeKey : Key|undefined = undefined;
        let userCodeData : {[key:string]:any} = {};
        try {
            userCodeKey = await this.keyStorage.getKey(KeyPrefix.userCode + userCode);
            userCodeData = JSON.parse(userCodeKey?.data ?? "{}");
        } catch (e) {

            // user code is invalid - tell user
            return {
                ok: false,
                error: "access_denied",
                error_description: "Invalid user code",
            }
        }

        if (!userCodeData.deviceCode) {
            // there is no device code in the user code data - delete
            CrossauthLogger.logger.error(j({msg: "No device code for user code", userCodeHash: Crypto.hash(userCode)}));
            await this.deleteUserCode(userCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "No device code for user code",
            }
        }

        let deviceCodeKey : Key;
        try {
            deviceCodeKey = await this.keyStorage.getKey(KeyPrefix.deviceCode + userCodeData.deviceCode);
        } catch (e) {
            // there is an invalid device code in the user code data - delete
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Invalid device code for user code", 
                userCodeHash: Crypto.hash(userCode), 
                deviceCodeHash: Crypto.hash(userCodeData.deviceCode), 
                cerr: ce}));
            await this.deleteUserCode(userCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "Invalid device code user code",
            }
        }
        let scope : string|undefined = undefined;
        let client_id : string|undefined = undefined;
        try {
            if (!deviceCodeKey.data) throw new CrossauthError(ErrorCode.UnknownError);
            const data = JSON.parse(deviceCodeKey.data);
            scope = data.scope;
            client_id = data.client_id;
            if (!client_id) throw new CrossauthError(ErrorCode.UnknownError)
        } catch (e) {
            await this.deleteUserCode(userCode);
            await this.deleteDeviceCode(userCodeData.deviceCode);
            return {
                ok: false,
                error: "server_error",
                error_description: "Unexpected or incomplete data in device code key",
            }
        }

        // ok - store this in the user code, along with the userid
        try {
            await this.keyStorage.updateData(KeyPrefix.deviceCode + userCodeData.deviceCode, "ok", true);
        } catch (e) {
            // error updating device code data, so delete both device code and user code
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.warn(j({msg: "Couldn't update status on user code entry - deleting", cerr: ce}));
            await this.deleteUserCode(userCode);
            await this.deleteDeviceCode(userCodeData.deviceCode);
            return {
                ok: false,
                error: "access_denied",
                error_description: "Invalid user code",
                client_id: client_id        
            };
        }
        
        // we no longer need the user code, so delete it
        await this.deleteUserCode(userCode);
        
        // tell the caller the user code enty was successful
        return {
            ok: true,
            scope,
            client_id: client_id
        }
    }

    async createMfaRequest(user: User): Promise<{
        mfa_token: string,
        error: string,
        error_description: string
    }> {
        const mfaToken = Crypto.randomValue(this.codeLength);
        const mfaKey = KeyPrefix.mfaToken + Crypto.hash(mfaToken);
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
                const mfaKey = KeyPrefix.mfaToken + Crypto.hash(mfaToken);
                key = await this.keyStorage.getKey(mfaKey);
                if (!key.userid) {
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
                    await this.userStorage?.getUserById(key.userid);
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

    /**
     * The OAuth Password MFA `challenge` endpoint
     * @param mfaToken as defined by the Password MFA spec
     * @param client_id as defined by the Password MFA spec
     * @param client_secret as defined by the Password MFA spec
     * @param challengeType as defined by the Password MFA spec
     * @param authenticatorId as defined by the Password MFA spec
     * @returns respond as defined by the Password MFA spec
     */
    async mfaChallengeEndpoint(mfaToken: string,
        client_id : string,
        client_secret : string|undefined,
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
        const clientResponse = await this.getClientById(client_id);
        if (!clientResponse.client) return clientResponse;    
        const client = clientResponse.client;

        // throw an error if client authentication is required not not present
        const clientAuthentication = 
            await this.authenticateClient(flow, client, client_secret);
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
                oobCode : Crypto.randomValue(this.codeLength),
            }
        }
        try {
            const authenticator = this.authenticators[mfa.user.factor2];
            if (!authenticator) {
                throw new CrossauthError(ErrorCode.Configuration,
                    "User's authenticator has not been loaded");
            }
            const resp = await authenticator.createOneTimeSecrets(mfa.user);
            await this.keyStorage.updateData(mfa.key.value,
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

    /**
     * Returns the OAuth flow type that corresonds to the given 
     * response type, scope and value for `code_challenge`
     * @param responseType OAuth `response_type`
     * @param scope Requested scopes (checks if it included `openid`)
     * @param codeChallenge the OAuth code challenge (checks if it is defined)
     * @returns returns the flow key from {@link @crossauth/common!OAuthFlows}
     */
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

    /**
     * Returns the OAuth flow type that corresonds to the given 
     * grant type and `code_verifier`
     * @param grantType OAuth `grant_type`
     * @param codeVerifier the OAuth code verifier (checks if it is defined)
     * @returns returns the flow key from {@link @crossauth/common!OAuthFlows}
     */
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
        } else if (grantType == "urn:ietf:params:oauth:grant-type:device_code") {
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

    async getAuthorizationCode(client: OAuthClient,
        redirect_uri: string,
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
        const decodedUri = redirect_uri; 
        OAuthClientManager.validateUri(decodedUri);
        if (this.requireRedirectUriRegistration && 
            !client.redirect_uri.includes(decodedUri)) {
            return {
                error: "invalid_request",
                error_description: `The redirect uri ${redirect_uri} is invalid`
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
            client_id: client.client_id,
            redirect_uri: redirect_uri,
        }
        if (scopes) {
            authzData.scope = scopes;
        }
        if (codeChallenge) {
            authzData.challengeMethod = codeChallengeMethod;
            // we store this as a hash for security.  If S256 is used, 
            // that will be a second hash
            authzData.challenge = Crypto.hash(codeChallenge);
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
                authzCode = Crypto.randomValue(this.codeLength);
                await this.keyStorage.saveKey(undefined,
                    KeyPrefix.authorizationCode + Crypto.hash(authzCode),
                    created,
                    expires,
                    authzDataString);
                success = true;
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: `Attempt number${i} at creating a unique authozation code failed`}));
            }
        }
        if (!success) {
            throw new CrossauthError(ErrorCode.KeyExists,
                "Couldn't create a authorization code");
        }

        return {code: authzCode, state: state};
    }

    async getAuthorizationCodeData(code: string) : Promise<{[key:string]:any}|undefined> {
            // recover scope, challenge and user from data persisted with 
            // authorization code
            let key : Key|undefined;
            let authzData : {[key:string]:any} = {}
            try {
                key = await this.keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code));
                authzData = KeyStorage.decodeData(key.data);
            } catch (e) {
                CrossauthLogger.logger.debug(j({err: e}));
                return undefined;
            }
            return authzData;
    }

    async deleteAuthorizationCodeData(code: string) {
        try {
            await this.keyStorage.deleteKey(KeyPrefix.authorizationCode+Crypto.hash(code));
        } catch (e) {
            CrossauthLogger.logger.warn(j({
                err: e,
                msg: "Couldn't delete authorization code from storage",
            }));
        }
}

    async setAuthorizationCodeData(code: string, fields: {[key:string]:any}) {
        const key = await this.keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code));
        key.data = JSON.stringify(fields);
        this.keyStorage.updateKey(key);
    }

    /**
     * Create an access token
     */
    async makeAccessToken({
        client, 
        code, 
        client_secret, 
        codeVerifier,  
        scopes, 
        issueRefreshToken = false, 
        user} : {
            client: OAuthClient, 
            code? : string, 
            client_secret? : string, 
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
            if (client.client_secret!=undefined) { 
                passwordCorrect = 
                    await Crypto.passwordsEqual(client_secret??"", 
                        client.client_secret??"");
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
            userid? : number|string,
            username? : string,
            [key:string] : any, 
        } = {};

        if (code) {

            // recover scope, challenge and user from data persisted with 
            // authorization code
            let key : Key|undefined;
            try {
                key = await this.keyStorage.getKey(KeyPrefix.authorizationCode+Crypto.hash(code));
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
                    client_id: client?.client_id
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
                    codeVerifier??"" : Crypto.sha256(codeVerifier??"");
            // we store the challenge in hashed form for security, 
            // so if S256 is used this will be a second hash
            if (Crypto.hash(hashedVerifier) != authzData.challenge) {
                return {
                    error: "access_denied",
                    error_description: "Code verifier is incorrect"
                };
            }
        }

        const now = new Date();
        const timeCreated = Math.ceil(now.getTime()/1000);
        let dateAccessTokenExpires : Date|undefined;


        if (scopes && scopes.includes("openid") || Object.keys(this.accessTokenClaims).length > 0) {

            if (this.userStorage && authzData.username) {
                try {
                    const {user : user1} = 
                        await this.userStorage.getUserByUsername(authzData.username);
                    user = user1;
                } catch (e) {
                    CrossauthLogger.logger.error(j({err: e}));
                    return {
                        error: "server_error",
                        error_description: "Couldn't load user data"
                    }
                }
            }
        }

        // create access token payload
        const accessTokenJti = Crypto.uuid();
        let accessTokenPayload : {[key:string]: any} = {
            jti: accessTokenJti,
            iat: timeCreated,
            iss: this.oauthIssuer,
            sub: authzData.username,
            type: "access",
        };
        // populate claims from custom set
        accessTokenPayload = this.addClaims(accessTokenPayload, this.accessTokenClaims, scopes, user);
        if (scopes) {
            accessTokenPayload.scope = scopes;
        }
        if (this.accessTokenExpiry != null) {
            accessTokenPayload.exp = timeCreated + this.accessTokenExpiry
            dateAccessTokenExpires = 
                new Date(now.getTime()+this.accessTokenExpiry*1000 + 
                    this.clockTolerance*1000);
        }
        if (this.audience) {
            accessTokenPayload.aud = this.audience;
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
                KeyPrefix.accessToken+Crypto.hash(accessTokenJti),
                now,
                dateAccessTokenExpires
            );
        }

        let idToken : string|undefined = undefined;

        if (scopes && scopes.includes("openid")) {

            // create id token payload
            const idokenJti = Crypto.uuid();
            let idTokenPayload : {[key:string]: any} = {
                aud: client.client_id,
                jti: idokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                sub: authzData.username,
                type: "id",
            };
            if (scopes.includes("email") && user?.email) {
                idTokenPayload.email = user.email;
            }
            if (scopes.includes("address") && user && "address" in user) {
                idTokenPayload.address = user.address;
            }
            if (scopes.includes("phone") && user && "phone" in user) {
                idTokenPayload.phone = user.phone;
            }
            if (scopes.includes("profile") && user) {
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

            // populate claims from custom set
            idTokenPayload = this.addClaims(idTokenPayload, this.idTokenClaims, scopes, user);
            
            idTokenPayload.scope = scopes;
            if (this.accessTokenExpiry != null) {
                idTokenPayload.exp = timeCreated + this.accessTokenExpiry
            }
    
            // create id token jwt
            idToken = await new Promise((resolve, reject) => {
                jwt.sign(idTokenPayload, this.secretOrPrivateKey, {
                    algorithm: this.jwtAlgorithmChecked,
                    keyid: this.jwtKid,
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

        let refreshToken : string|undefined = undefined;
        if (issueRefreshToken) { 
            // create refresh token 
            //refreshToken = Crypto.randomValue(this.codeLength); 

            const refreshData : {[key:string]: any} = {
                username: authzData.username,
                client_id: client.client_id,

            }
            if (scopes) {
                refreshData.scope = scopes;
            }
            let refreshTokenExpires : Date|undefined = undefined;
            // create refresh token payload
            const refreshTokenJti = Crypto.uuid();
            const refreshTokenPayload : {[key:string]: any} = {
                jti: refreshTokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                sub: authzData.username,
                type: "refresh",
            };
            if (this.refreshTokenExpiry != null) {
                refreshTokenPayload.exp = timeCreated + this.refreshTokenExpiry
                refreshTokenExpires = 
                    this.refreshTokenExpiry ? 
                        new Date(timeCreated + this.refreshTokenExpiry*1000 + 
                            this.clockTolerance*1000) : 
                        undefined;
            }
            if (this.oauthIssuer) {
                refreshTokenPayload.aud = this.oauthIssuer;
            }
    
            // create refresh token jwt
            refreshToken = await new Promise((resolve, reject) => {
                jwt.sign(refreshTokenPayload,
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

            // save refresh token
            if (refreshToken) {
                await this.keyStorage?.saveKey(
                    undefined, // to avoid user storage dependency
                    KeyPrefix.refreshToken+Crypto.hash(refreshToken),
                    now,
                    refreshTokenExpires,
                    JSON.stringify(refreshData)
                );
            }
        }
        
        return {
            access_token : accessToken,
            id_token: idToken,
            refresh_token : refreshToken,
            expires_in : this.accessTokenExpiry==null ? undefined : 
                this.accessTokenExpiry,
            token_type: "Bearer",
            scope: scopes? scopes.join(" ") : undefined,
        }
    }

    /**
     * Create an access token
     */
    async createTokensFromPayload(clientId : string, accessPayload? : {[key:string]:any}, 
        idPayload? : {[key:string]:any}) 
        : Promise<{
            access_token?: string, 
            id_token? : string, 
            access_payload?: {[key:string]:any}, 
            id_payload? : {[key:string]:any}, 
            expires_in: number|undefined, 
            token_type : string}> {

        const now = new Date();
        const timeCreated = Math.ceil(now.getTime()/1000);
        let dateAccessTokenExpires : Date|undefined;

        let accessToken : string|undefined = undefined;
        let idToken : string|undefined = undefined;
        let accessTokenPayload : {[key:string]:any}|undefined = undefined;

        // create access token payload
        if (accessPayload) {
            const accessTokenJti = Crypto.uuid();
            let accessTokenPayload1 : {[key:string]: any} = {
                ...accessPayload,
                jti: accessTokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                type: "access",
            };
            if (this.accessTokenExpiry != null) {
                accessTokenPayload1.exp = timeCreated + this.accessTokenExpiry
                dateAccessTokenExpires = 
                    new Date(now.getTime()+this.accessTokenExpiry*1000 + 
                        this.clockTolerance*1000);
            }
            if (this.audience) {
                accessTokenPayload1.aud = this.audience;
            }
    
            // create access token jwt
            accessToken = await new Promise((resolve, reject) => {
                jwt.sign(accessTokenPayload1,
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
            accessTokenPayload = accessTokenPayload1;

            // persist access token if requested
            if (this.persistAccessToken && this.keyStorage) {
                await this.keyStorage?.saveKey(
                    undefined, // to avoid user storage dependency, we don't set this
                    KeyPrefix.accessToken+Crypto.hash(accessTokenJti),
                    now,
                    dateAccessTokenExpires
                );
            }
        }


        if (idPayload != undefined) {

            // create id token payload
            const idokenJti = Crypto.uuid();
            idPayload = {
                ...idPayload,
                aud: clientId,
                jti: idokenJti,
                iat: timeCreated,
                iss: this.oauthIssuer,
                type: "id",
            };
    
            // create id token jwt
            if (idPayload) {
                const payload1 : {[key:string]:any} = idPayload;
                idToken = await new Promise((resolve, reject) => {
                    jwt.sign(payload1, this.secretOrPrivateKey, {
                        algorithm: this.jwtAlgorithmChecked,
                        keyid: this.jwtKid,
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
    
        }
        
        return {
            access_token : accessToken,
            id_token: idToken,
            access_payload: accessTokenPayload,
            id_payload: idPayload,
            expires_in : this.accessTokenExpiry==null ? undefined : 
                this.accessTokenExpiry,
            token_type: "Bearer",
        }
    }

    private addClaims(tokenPayload : {[key:string]:any}, 
        claims : {[key:string] : any},
        scopes: string[]|undefined,
        user: User|undefined) : {[key:string]:any} {
        if (user) {
            if (scopes) {
                for (let scope of scopes) {
                    if (scope in claims) {
                        if (claims[scope] == "all") {
                            tokenPayload = {
                                ...tokenPayload,
                                ...user
                            };
                        } else {
                            let allClaims = claims[scope];
                            if (typeof(allClaims) == "string") allClaims = [allClaims];
                            for (let field in allClaims) {
                                tokenPayload[field] = 
                                    user[allClaims[field]];
                            }
                        }

                    }
                }
            } 
            if ("all" in claims) {
                let allClaims = claims["all"]
                if (typeof(allClaims) == "string") allClaims = [allClaims];
                if (allClaims == "all") {
                    tokenPayload = {
                        ...tokenPayload,
                        ...user
                    };
                } else {
                    for (let field in allClaims) {
                        tokenPayload[field] = 
                            user[allClaims[field]];
                    }
                }
            }
        }

        return tokenPayload;

    }

    /**
     * Returns whether the given authorization code is valid (in the database)
     * 
     * @param code the authorization code to look up
     * @returns true or false
     */
    async validAuthorizationCode(code : string) : 
        Promise<boolean> {
        try {
            const hash = KeyPrefix.authorizationCode + Crypto.hash(code);
            await this.keyStorage.getKey(hash);
            return true;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return false;
        }
    }

    /**
     * Returns whether the given refresh token is valid (in the database)
     * 
     * @param token the refresh token to look up
     * @returns true or false
     */
    async validRefreshToken(token : string) : 
        Promise<boolean> {
        try {
            const hash = KeyPrefix.refreshToken + Crypto.hash(token);
            await this.keyStorage.getKey(hash);
            return true;
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return false;
        }
    }

    /**
     * Gets the data associated with the refresh token from the database.
     * @param token the refresh token to fetch
     * @returns the object parsed from the stored JSON data for the token,
     *          or undefined if there was an error
     */
    async getRefreshTokenData(token? : string) : 
        Promise<{[key:string]:any}|undefined> {
        if (!token) return undefined;
        try {
            const hash = KeyPrefix.refreshToken + Crypto.hash(token);
            const key = await this.keyStorage.getKey(hash);
            return JSON.parse(key.data||"{}");
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            return undefined;
        }
    }

    /**
     * Validates a JWT token, returning its payload or undefined if it
     * is invalid.
     * 
     * @param token the token to validate
     * @returns the payload or undefinedf if there was an error
     */
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

    /**
     * Validates a JWT access token, returning its payload or undefined if it
     * is invalid.
     * 
     * @param token the token to validate
     * @returns the payload or undefinedf if there was an error ir the 
     * `type` field in the payload is not `access`.
     */
    async validAccessToken(token : string) : 
        Promise<{[key:string]: any}|undefined> {
        try {
            const decoded = await this.validateJwt(token, "access");
            if (this.persistAccessToken) {
                const hash = KeyPrefix.accessToken + Crypto.hash(decoded.payload.jti);
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

    /**
     * Appends the scope and state to the redirect URI
     * @param redirect_uri the redirect URI, whicvh may already contain
     *        query parameters
     * @param code the authorization code to append
     * @param state the state to append
     * @returns the new URL as a string.
     */
    redirect_uri(redirect_uri : string, code : string, state : string) : string {
        const sep = redirect_uri.includes("?") ? "&" : "?";
        return `${redirect_uri}${sep}code=${code}&state=${state}`;
    }

    /**
     * @returns all the response types that are supported.
     */
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

    /**
     * Returns an OIDC configuration object based on this authorization
     * server's configuration
     * @param options 
     *        - `authorizeEndpoint` the URL for the `authorize` endpoint
     *        - `tokenEndpoint` the URL for the `token` endpoint
     *        - `jwksUri` the URL for the `jwks` endpoint
     *        - `additionalClaims` additional claims that can be returned
     *          in an ID token ("iss", "sub", "aud", "jti", "iat", "type"
     *          are always included)
     * @returns the OIDC configuration
     */
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

    /**
     * Returns the public key for validating JWT signatures.
     * 
     * If there isn't one, returns an empty array.
     * @returns an array of keys with exactly one or zero entries.
     */
    jwks() : Jwks {
        let keys : JsonWebKey[] = [];
        if (this.jwtPublicKey) {
            const publicKey = 
                createPublicKey(this.jwtPublicKey).export({format: "jwk"});
            //const publicKey = await jose.importSPKI(this.jwtPublicKey, this.jwtKeyType);

            publicKey.kid = "1";
            publicKey.alg = this.jwtKeyType;
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
     * Validates the parameters passed to the `authorize` endpoint
     * 
     * This doesn't query a user or look anything up in the database.
     * It just checks that they have valid syntax.
     * 
     * @param options these parameters correspond to the OAuth specification
     * @returns an empty object or an error if the parameters were not valid
     */
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
