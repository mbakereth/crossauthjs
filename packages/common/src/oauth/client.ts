// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { CrossauthLogger, j } from '..';
import { CrossauthError, ErrorCode } from '..';
import {
    OpenIdConfiguration,
    OAuthTokenConsumerBase,
    DEFAULT_OIDCCONFIG,
    type GrantType } from '..';
import * as jose from 'jose'

/**
 * Crossauth allows you to define which flows are valid for a given client.
 */
export class OAuthFlows {

    /** All flows are allowed */
    static readonly All = "all";

    /** OAuth authorization code flow (without PKCE) */
    static readonly AuthorizationCode = "authorizationCode";

    /** OAuth authorization code flow with PKCE */
    static readonly AuthorizationCodeWithPKCE = "authorizationCodeWithPKCE";

    /** Auth client credentials flow */
    static readonly ClientCredentials = "clientCredentials";

    /** OAuth refresh token flow */
    static readonly RefreshToken = "refreshToken";

    /** OAuth device code flow */
    static readonly DeviceCode = "deviceCode";

    /** OAuth password flow */
    static readonly Password = "password";

    /** The Auth0 password MFA extension to the password flow */
    static readonly PasswordMfa = "passwordMfa";

    /** The OpenID Connect authorization code flow, with or without
     * PKCE.
     */
    static readonly OidcAuthorizationCode = "oidcAuthorizationCode";

    /** A user friendly name for the given flow ID
     * 
     * For example, if you pass "authorizationCode" 
     * (`OAuthFlows.AuthorizationCode`) you will get `"Authorization Code"`.
     */
    static readonly flowName : {[key:string]:string} = {
        [OAuthFlows.AuthorizationCode] : "Authorization Code",
        [OAuthFlows.AuthorizationCodeWithPKCE] : "Authorization Code with PKCE",
        [OAuthFlows.ClientCredentials] : "Client Credentials",
        [OAuthFlows.RefreshToken] : "Refresh Token",
        [OAuthFlows.DeviceCode] : "Device Code",
        [OAuthFlows.Password] : "Password",
        [OAuthFlows.PasswordMfa] : "Password MFA",
        [OAuthFlows.OidcAuthorizationCode] : "OIDC Authorization Code",
    }

    /**
     * Returns a user-friendly name for the given flow strings.
     * 
     * The value returned is the one in `flowName`.
     * @param flows the flows to return the names of
     * @returns an array of strings
     */
    static flowNames(flows : string[]) : {[key:string]:string} {
        let ret : {[key:string]:string} = {};
        flows.forEach((flow) => {
            if (flow in OAuthFlows.flowName) ret[flow] = OAuthFlows.flowName[flow];
        });
        return ret;
    }
    
    /**
     * Returns true if the given string is a valid flow name.
     * @param flow the flow to check
     * @returns true or false.
     */
    static isValidFlow(flow : string) : boolean {
        return OAuthFlows.allFlows().includes(flow);
    }

    /**
     * Returns true only if all given strings are valid flows
     * @param flows the flows to check
     * @returns true or false.
     */
    static areAllValidFlows(flows : string[]) : boolean {
        let valid = true;
        flows.forEach((flow) => {
            if (!OAuthFlows.isValidFlow(flow)) valid = false;
        });
        return valid;
    }

    static allFlows() : string[] {
        return [OAuthFlows.AuthorizationCode,
            OAuthFlows.AuthorizationCodeWithPKCE,
            OAuthFlows.ClientCredentials,
            OAuthFlows.RefreshToken,
            OAuthFlows.DeviceCode,
            OAuthFlows.Password,
            OAuthFlows.PasswordMfa,
            OAuthFlows.OidcAuthorizationCode,
        ];
    }

    /**
     * Returns the OAuth grant types that are valid for a given flow, or 
     * `undefined` if it is not a valid flow.
     * @param oauthFlow the flow to get the grant type for.
     * @returns a {@link GrantType} value
     */
    static grantType(oauthFlow : string) : GrantType[]|undefined {
        switch (oauthFlow) {
            case OAuthFlows.AuthorizationCode:
            case OAuthFlows.AuthorizationCodeWithPKCE:
                case OAuthFlows.OidcAuthorizationCode:
                    return ["authorization_code"];
            case OAuthFlows.ClientCredentials:
                return ["client_credentials"];
            case OAuthFlows.RefreshToken:
                return ["refresh_token"];
            case OAuthFlows.Password:
                return ["password"];
            case OAuthFlows.PasswordMfa:
                return ["http://auth0.com/oauth/grant-type/mfa-otp", "http://auth0.com/oauth/grant-type/mfa-oob"];
            case OAuthFlows.DeviceCode:
                return ["urn:ietf:params:oauth:grant-type:device_code"];
        }
        return undefined;
    }
} 

/**
 * These are the fields that can be returned in the JSON from an OAuth
 * call.
 */
export interface OAuthTokenResponse {
    access_token?: string,
    refresh_token? : string, 
    id_token? : string, 
    id_payload? : {[key:string]:any},
    token_type?: string, 
    expires_in?: number,
    error? : string,
    error_description? : string,
    scope?: string,
    mfa_token? : string,
    oob_channel? : string,
    oob_code? : string,
    challenge_type? : string,
    binding_method? : string,
    name? : string,
}

/**
 * These are the fields that can be returned in the device_authorization
 * device code flow endpoint.
 */
export interface OAuthDeviceAuthorizationResponse {
    device_code?: string,
    user_code? : string, 
    verification_uri? : string, 
    verification_uri_complete?: string, 
    expires_in?: number,
    interval?: number,
    error? : string,
    error_description? : string,
}

/**
 * These are the fields that can be returned in the device
 * device code flow endpoint.
 */
export interface OAuthDeviceResponse {
    ok: boolean,
    client_id?: string,
    scopeAuthorizationNeeded? : boolean,
    scope? : string,
    error? : string,
    error_description? : string,
}

/**
 * An abstract base class for OAuth clients.
 * 
 * Crossauth provides OAuth clients that work in the browser as well as in
 * Node.  This base class contains all the non-interpreter specific 
 * functionality.  What is missing is the cryptography which is included
 * in derived Node-only and Browser-only classes.  
 * See `@crossauth/backend/OAuthClientBackend`.
 * 
 * Flows supported are Authorization Code Flow with and without PKCE,
 * Client Credentials, Refresh Token, Password and Password MFA.  The
 * latter is defined at
 * {@link https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors}.
 * 
 * It also supports the OpenID Connect Authorization Code Flow, with and 
 * without PKCE.
 */
export abstract class OAuthClientBase {
    protected authServerBaseUrl = "";
    #client_id : string|undefined;
    #client_secret : string|undefined;
    protected codeChallengeMethod : "plain" | "S256" = "S256";
    protected verifierLength = 32;
    protected redirect_uri : string|undefined;
    protected stateLength = 32;
    protected authzCode : string = "";
    protected oidcConfig : (OpenIdConfiguration&{[key:string]:any})|undefined;
    protected tokenConsumer : OAuthTokenConsumerBase;
    protected authServerHeaders : {[key:string]:string} = {};
    protected authServerMode :  "no-cors" | "cors" | "same-origin" | undefined = undefined;
    protected authServerCredentials : "include" | "omit" | "same-origin" | undefined = undefined;
    protected oauthPostType : "json" | "form" = "json";
    protected oauthLogFetch = false;
    protected oauthUseUserInfoEndpoint = false;
    protected oauthAuthorizeRedirect : string|undefined = undefined;

    /**
     * Constructor.
     * 
     * @param options options:
     *      - `authServerBaseUrl` the base URI for OAuth calls.  This is
     *        the value in the isser field of a JWT.  The client will
     *        reject any JWTs that are not from this issuer.
     *      - `client_id` the client ID for this client.
     *      - `redriectUri` when making OAuth calls, this value is put
     *        in the redirect_uri field.
     *      - `number` of characters (before base64-url-encoding) for generating
     *        state values in OAuth calls.
     *      - `verifierLength` of characters (before base64-url-encoding) for
     *        generating PKCE values in OAuth calls.
     *      - `tokenConsumer` to keep this class independent of frontend 
     *        and backend specific funtionality (eg classes not available
     *        in browsers), the token consumer, which determines if a token
     *        is valid or not, is abstracted out.
     *      - authServerCredentials credentials flag for fetch calls to the
     *        authorization server
     *      - authServerMode mode flag for fetch calls to the 
     *        authorization server
     *      - authServerHeaders headers flag for calls to the
     *        authorization server
     *      - `receiveTokensFn` if defined, this will be called when tokens
     *        are received
     */
    constructor({authServerBaseUrl,
        client_id,
        client_secret,
        redirect_uri,
        codeChallengeMethod,
        stateLength,
        verifierLength,
        tokenConsumer,
        authServerCredentials,
        authServerMode,
        authServerHeaders,
    } : {
        authServerBaseUrl : string,
        stateLength? : number,
        verifierLength? : number,
        client_id? : string,
        client_secret? : string,
        redirect_uri? : string,
        codeChallengeMethod? : "plain" | "S256",
        tokenConsumer : OAuthTokenConsumerBase,
        authServerHeaders? : {[key:string]:string},
        authServerCredentials? :"include" | "omit" | "same-origin" | undefined,
        authServerMode? : "no-cors" | "cors" | "same-origin" | undefined,

    }) {
        this.tokenConsumer = tokenConsumer;
        this.authServerBaseUrl = authServerBaseUrl;
        if (verifierLength) this.verifierLength = verifierLength;
        if (stateLength) this.stateLength = stateLength;
        if (client_id) this.#client_id = client_id;
        if (client_secret) this.#client_secret = client_secret;
        if (redirect_uri) this.redirect_uri = redirect_uri;
        if (codeChallengeMethod) this.codeChallengeMethod = codeChallengeMethod;
        this.authServerBaseUrl = authServerBaseUrl;
        if (authServerCredentials) this.authServerCredentials = authServerCredentials;
        if (authServerMode) this.authServerMode = authServerMode;
        if (authServerHeaders) this.authServerHeaders = authServerHeaders;

    }

    set client_id(value : string) {
        this.#client_id = value;
    }
    set client_secret(value : string) {
        this.#client_secret = value;
    }

    /**
     * Loads OpenID Connect configuration so that the client can determine
     * the URLs it can call and the features the authorization server provides.
     * 
     * @param oidcConfig if defined, loadsa the config from this object.
     *        Otherwise, performs a fetch by appending
     *        `/.well-known/openid-configuration` to the 
     *        `authServerBaseUrl`.
     * @throws {@link @crossauth/common!CrossauthError} with the following {@link @crossauth/common!ErrorCode}s
     *   - `Connection` if data from the URL could not be fetched or parsed.
     */
    async loadConfig(oidcConfig? : OpenIdConfiguration) : Promise<void> {
        if (oidcConfig) {
            CrossauthLogger.logger.debug(j({msg: "Reading OIDC config locally"}))
            this.oidcConfig = oidcConfig;
            return;
        }

        let resp : Response|undefined = undefined;
        try {
            const url = new URL(
                this.authServerBaseUrl + "/.well-known/openid-configuration");
            CrossauthLogger.logger.debug(j({msg: `Fetching OIDC config from ${url}`}))
            let options : {[key:string]:any} = {headers: this.authServerHeaders};
            if (this.authServerMode) options.mode = this.authServerMode;
            if (this.authServerCredentials) options.credentials = this.authServerCredentials;
            resp = await fetch(url, options);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
        }
        if (!resp || !resp.ok) {
            throw new CrossauthError(ErrorCode.Connection, 
                "Couldn't get OIDC configuration from URL" + this.authServerBaseUrl + "/.well-known/openid-configuration");
        }
        this.oidcConfig = {...DEFAULT_OIDCCONFIG};
        try {
            const body = await resp.json();
            for (const [key, value] of Object.entries(body)) {
                this.oidcConfig[key] = value;
            }
        } catch (e) {
            throw new CrossauthError(ErrorCode.Connection, 
                "Unrecognized response from OIDC configuration endpoint");
        }
    }

    getOidcConfig() {
        return this.oidcConfig;
    }

    /**
     * Produce a random Base64-url-encoded string, whose length before 
     * base64-url-encoding is the given length,
     * @param length the length of the random array before base64-url-encoding.
     * @returns the random value as a Base64-url-encoded srting
     */
    protected abstract randomValue(length : number) : string;

    /**
     * SHA256 and Base64-url-encodes the given test
     * @param plaintext the text to encode
     * @returns the SHA256 hash, Base64-url-encode
     */
    protected abstract sha256(plaintext :string) : Promise<string>;

    //////////////////////////////////////////////////////////////////////
    // Authorization Code Flow

    /**
     * Starts the authorizatuin code flow, optionally with PKCE.
     * 
     * Doesn't actually call the endpoint but rather returns its URL
     * 
     * @param scope optionally specify the scopes to ask the user to
     *        authorize (space separated, non URL-encoded)
     * @param pkce if true, initiate the Authorization Code Flow with PKCE,
     *        otherwiswe without PKCE.
     * @returns an object with
     *          - `url` - the full `authorize` URL to fetch, if there was no
     *            error, undefined otherwise
     *          - `error` OAuth error if there was an error, undefined
     *            otherwise.  See OAuth specification for authorize endpoint
     *          - `error_description` friendly error message or undefined
     *            if no error
     */
    async startAuthorizationCodeFlow(state: string, 
        scope?: string,
        codeChallenge? : string, 
        pkce: boolean = false) : 
        Promise<{
            url?: string,
            error?: string,
            error_description?: string
        }> {
        CrossauthLogger.logger.debug(j({msg: "Starting authorization code flow"}));
        if (!this.oidcConfig) await this.loadConfig();      
        if (!this.oidcConfig?.response_types_supported.includes("code")
            || !this.oidcConfig?.response_modes_supported.includes("query")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support authorization code flow"
            };
        }
        if (!this.oidcConfig?.authorization_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get authorize endpoint"
            };
        }
        if (!this.#client_id) return {
            error: "invalid_request",
            error_description: "Cannot make authorization code flow without client id"
        }; 
        if (!this.redirect_uri) return {
            error: "invalid_request",
            error_description: "Cannot make authorization code flow without Redirect Uri"
        }; 

        let base = this.oidcConfig.authorization_endpoint;
        if (this.oauthAuthorizeRedirect) base = this.oauthAuthorizeRedirect;

        let url = base 
            + "?response_type=code"
            + "&client_id=" + encodeURIComponent(this.#client_id)
            + "&state=" + encodeURIComponent(state)
            + "&redirect_uri=" + encodeURIComponent(this.redirect_uri);

        if (scope) {
            url += "&scope=" + encodeURIComponent(scope);
        }

        if (pkce && codeChallenge) {
            url += "&code_challenge=" + codeChallenge;
        }

        return {url: url};
    }

    protected async codeChallengeAndVerifier() {
        const codeVerifier = this.randomValue(this.verifierLength);
        const codeChallenge = 
            this.codeChallengeMethod == "plain" ? 
            codeVerifier : await this.sha256(codeVerifier);
        return {codeChallenge, codeVerifier}
    }

    async getIdPayload(id_token : string, access_token? : string) : Promise<{payload?: {[key:string]:any}, error? : string, error_description? : string}> {
        let error : string|undefined = undefined;
        let error_description : string|undefined = undefined;
        try {
            let payload : {[key:string]:any}|undefined = undefined;

            payload = await this.validateIdToken(id_token);
            if (!payload) {
                error = "access_denied";
                error_description = "Invalid ID token received";
                return {error, error_description}
            }
            if (access_token) {
                if (this.oauthUseUserInfoEndpoint) {
                    const userInfo = await this.userInfoEndpoint(access_token)
                    if (userInfo.error) {
                        error = userInfo.error;
                        error_description = "Failed getting user info: " + (userInfo.error_description ?? "unknown error");
                        return {error, error_description}
                    }
                    payload = {...payload, ...userInfo}
                }
            }
            return {payload}
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Couldn't get user info", cerr: ce}));
            error = ce.oauthErrorCode;
            error_description = "Couldn't get user info: " + ce.message;
            return {error, error_description};
        }
    }

    async getAccessPayload(access_token : string, checkAudience? : boolean) : Promise<{payload?: {[key:string]:any}, error? : string, error_description? : string}> {
        let error : string|undefined = undefined;
        let error_description : string|undefined = undefined;
        try {
            let payload : {[key:string]:any}|undefined = undefined;

            payload = await this.validateAccessToken(access_token, checkAudience); 
            if (!payload) {
                error = "access_denied";
                error_description = "Invalid access token received";
                return {error, error_description}
            }
            return {payload}
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: "Couldn't get user info", cerr: ce}));
            error = ce.oauthErrorCode;
            error_description = "Couldn't get user info: " + ce.message;
            return {error, error_description};
        }
    }

    /**
     * This implements the functionality behind the redirect URI
     * 
     * Does not throw exceptions.
     *
     * If an error wasn't reported,  a POST request to the `token` endpoint with 
     * the authorization code to get an access token, etc.  If there was 
     * an error, this is just passed through without calling and further
     * endpoints.
     * 
     * @param code the authorization code
     * @param state the random state variable
     * @param error if defined, it will be returned as an error.  This is
     *              for cascading errors from previous requests.
     * @param errorDescription if error is defined, this text is returned
     *        as the `error_description`  It is set to `Unknown error` 
     *        otherwise
     * @returns The {@link OAuthTokenResponse} from the `token` endpoint
     *          request, or `error` and `error_description`.
     */
    async redirectEndpoint(code?: string, scope?: string,
        codeVerifier? : string,
        error?: string,
        errorDescription?: string) : Promise<OAuthTokenResponse>{
        if (!this.oidcConfig) await this.loadConfig();      
        if (error || !code) {
            if (!error) error = "server_error";
            if (!errorDescription) errorDescription = "Unknown error";
            return {error, error_description: errorDescription};
        }
        this.authzCode = code;    

        if (!this.oidcConfig?.grant_types_supported.includes("authorization_code")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support authorization code grant"
            };
        }
        if (!this.oidcConfig?.token_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get token endpoint"
        };
        }
        const url = this.oidcConfig.token_endpoint;

        let grant_type : string;
        let client_secret : string|undefined;
        grant_type = "authorization_code";
        client_secret = this.#client_secret;
        let params : {[key:string]:any} = {
            grant_type: grant_type,
            client_id: this.#client_id,
            code: this.authzCode,
            redirect_uri: this.redirect_uri,
        }
        if (scope) params.scope = scope;
        if (client_secret) params.client_secret = client_secret;
        if (codeVerifier) params.code_verifier = codeVerifier;
        try {
            let resp = await this.post(url, params, this.authServerHeaders);
            if (resp.id_token) {
                const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
                if (userInfo.error) {
                    return userInfo;
                }
                resp.id_payload = userInfo.payload;
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Unable to get access token from server"
            };
        }
    }

    //////////////////////////////////////////////////////////////////////
    // Client Credentials Flow

    /**
     * Performs the client credentials flow.
     * 
     * Does not throw exceptions.
     * 
     * Makes a POST request to the `token` endpoint with the
     * authorization code to get an access token, etc.
     * 
     * @param scope the scopes to authorize for the client (optional)
     * @returns The {@link OAuthTokenResponse} from the `token` endpoint
     *          request, or `error` and `error_description`.
     */
    async clientCredentialsFlow(scope? : string) : 
        Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Starting client credentials flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported.includes("client_credentials")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support client credentials grant"
            };
        }
        if (!this.oidcConfig?.token_endpoint) {
            return {error: "server_error", error_description: "Cannot get token endpoint"};
        }
        if (!this.#client_id) return {
            error: "invalid_request",
            error_description: "Cannot make client credentials flow without client id"
        }; 
        // Actually you can if it is not a confidential client (although not recommended)
        /*if (!this.#client_secret) return {
            error: "invalid_request",
            error_description: "Cannot make client credentials flow without client secret"
        }; */

        const url = this.oidcConfig.token_endpoint;

        let params : {[key:string]:any} = {
            grant_type: "client_credentials",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
        }
        if (scope) params.scope = scope;
        try {
            let resp = await this.post(url, params, this.authServerHeaders);
            if (resp.id_token) {
                const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
                if (userInfo.error) {
                    return userInfo;
                }
                resp.id_payload = userInfo.payload;
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    //////////////////////////////////////////////////////////////////////
    // Password and Password MFA Flows

    /** Initiates the Password Flow.
     * 
     * Does not throw exceptions.
     * 
     * @param username the username
     * @param password the user's password
     * @param scope the scopes to authorize (optional)
     * @returns An {@link OAuthTokenResponse} which may contain data or
     * the OAuth error fields.  If 2FA is enabled for this user on the
     * authorization server, the Password MFA flow is followed.  See
     * {@link https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors}.
     * 
     */
    async passwordFlow(username: string,
        password: string,
        scope?: string) : 
        Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Starting password flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported.includes("password")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password grant"
            };
        }
        if (!this.oidcConfig?.token_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get token endpoint"
            };
        }

        const url = this.oidcConfig.token_endpoint;

        let params : {[key:string]:any} = {
            grant_type: "password",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            username : username,
            password : password,
        }
        if (scope) params.scope = scope;
        try {
            let resp = await this.post(url, params, this.authServerHeaders);
            if (resp.id_token) {
                const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
                if (userInfo.error) {
                    return userInfo;
                }
                resp.id_payload = userInfo.payload;
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    /** Request valid authenticators using the Password MFA flow, 
     * after the Password flow has been initiated.
     * 
     * Does not throw exceptions.
     * 
     * @param mfaToken the MFA token that was returned by the authorization
     *        server in the response from the Password Flow.
     * @returns Either
     *   - authenticators an array of {@link MfaAuthenticatorResponse} objects,
     *     as per Auth0's Password MFA documentation
     *   - an `error` and `error_description`, also as per Auth0's Password MFA 
     *     documentation
     */
    async mfaAuthenticators(mfaToken : string) : 
        Promise<{
            authenticators?: MfaAuthenticatorResponse[],
            error?: string,
            error_description?: string
        }> {
        CrossauthLogger.logger.debug(j({msg: "Getting valid MFA authenticators"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-otp") &&
            this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-oob")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password_mfa grant"
            };
        }
        if (!this.oidcConfig?.issuer) {
            return {error: "server_error", error_description: "Cannot get issuer"};
        }

        const url = 
            this.oidcConfig.issuer + (this.oidcConfig.issuer.endsWith("/") ? 
            "" : "/") + "mfa/authenticators";
        const resp = 
            await this.get(url, {'authorization': 'Bearer ' + mfaToken, ...this.authServerHeaders});
        if (!Array.isArray(resp)) {
            return {
                error: "server_error",
                error_description: "Expected array of authenticators in mfa/authenticators response"
            };
        }
        let authenticators : MfaAuthenticatorResponse[] = [];
        for (let i=0; i<resp.length; ++i) {
            const authenticator = resp[i];
            if (!authenticator.id || !authenticator.authenticator_type || 
                !authenticator.active) {
                return {
                    error: "server_error",
                    error_description: "Invalid mfa/authenticators response"
                };
            }
            authenticators.push({
                id: authenticator.id,
                authenticator_type: authenticator.authenticator_type,
                active: authenticator.active,
                name: authenticator.name,
                oob_channel: authenticator.oob_channel,
            });
        }
        return {authenticators};

    }

    /** 
     * This is part of the Auth0 Password MFA flow.  Once the client has
     * received a list of valid authenticators, if it wishes to initiate
     * OTP, call this function
     * 
     * Does not throw exceptions.
     * 
     * @param mfaToken the MFA token that was returned by the authorization
     *        server in the response from the Password Flow.
     * @param authenticatorId the authenticator ID, as returned in the response
     * from the `mfaAuthenticators` request.
     */
    async mfaOtpRequest(mfaToken: string,
        authenticatorId: string) : 
        Promise<{
            challenge_type? : string, 
            error? : string, 
            error_description? : string}> {
        CrossauthLogger.logger.debug(j({msg: "Making MFA OTB request"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-otp")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password_mfa grant"
            };
        }
        if (!this.oidcConfig?.issuer) {
            return {error: "server_error", error_description: "Cannot get issuer"};
        }

        const url = this.oidcConfig.issuer + 
            (this.oidcConfig.issuer.endsWith("/") ? "" : "/") + "mfa/challenge";
        const resp = await this.post(url, {
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            challenge_type: "otp",
            mfa_token: mfaToken,
            authenticator_id: authenticatorId,
        }, this.authServerHeaders);
        if (resp.challenge_type != "otp") {
            return {
                error: resp.error ?? "server_error",
                error_description: resp.error_description ?? "Invalid OTP challenge response"
            };
        }

        return resp;
    }

    /**
     * Completes the Password MFA OTP flow.
     * @param mfaToken the MFA token that was returned by the authorization
     *        server in the response from the Password Flow.
     * @param otp the OTP entered by the user
     * @returns an object with some of the following fields, depending on
     *          authorization server configuration and whether there were
     *          errors:
     *   - `access_token` an OAuth access token
     *   - `refresh_token` an OAuth access token
     *   - `id_token` an OpenID Connect ID token
     *   - `expires_in` number of seconds when the access token expires
     *   - `scope` the scopes the user authorized
     *   - `token_type` the OAuth token type
     *   - `error` as per Auth0 Password MFA documentation
     *   - `error_description` friendly error message
     */
    async mfaOtpComplete(
        mfaToken: string,
        otp: string,
        scope?: string) : 
        Promise<{
        access_token? : string, 
        refresh_token? : string, 
        id_token?: string, 
        expires_in? : number, 
        scope? : string, 
        token_type?: string, 
        error? : string, 
        error_description? : string}> {
        CrossauthLogger.logger.debug(j({msg: "Completing MFA OTP request"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-otp")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password_mfa grant"
            };
        }
        if (!this.oidcConfig?.issuer) {
            return {error: "server_error", error_description: "Cannot get issuer"};
        }

        const otpUrl = this.oidcConfig.token_endpoint;
        const otpResp = await this.post(otpUrl, {
            grant_type: "http://auth0.com/oauth/grant-type/mfa-otp",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            challenge_type: "otp",
            mfa_token: mfaToken,
            otp: otp,
            scope: scope,
        }, this.authServerHeaders);
        if (otpResp.id_token) {
            const userInfo = await this.getIdPayload(otpResp.id_token, otpResp.access_token);
            if (userInfo.error) {
                return userInfo;
            }
            otpResp.id_payload = userInfo.payload;
        }
    return {
            id_token: otpResp.id_token,
            access_token: otpResp.access_token,
            refresh_token: otpResp.refresh_token,
            expires_in: Number(otpResp.expires_in),
            scope: otpResp.scope,
            token_type: otpResp.token_type,
            error: otpResp.error,
            error_description: otpResp.error_description,
        }

    }

    /** 
     * This is part of the Auth0 Password MFA flow.  Once the client has
     * received a list of valid authenticators, if it wishes to initiate
     * OOB (out of band) login, call this function
     * 
     * Does not throw exceptions.
     * 
     * @param mfaToken the MFA token that was returned by the authorization
     *        server in the response from the Password Flow.
     * @param authenticatorId the authenticator ID, as returned in the response
     * from the `mfaAuthenticators` request.
     * @returns an object with one or more of the following defined:
     *   - `challenge_type` as per the Auth0 MFA documentation
     *   - `oob_code` as per the Auth0 MFA documentation
     *   - `binding_method` as per the Auth0 MFA documentation
     *   - `error` as per Auth0 Password MFA documentation
     *   - `error_description` friendly error message
     */
    async mfaOobRequest(mfaToken : string, 
        authenticatorId : string, ) : Promise<{
        challenge_type? : string, 
        oob_code? : string, 
        binding_method?: string, 
        error? : string, 
        error_description? : string}> {
        CrossauthLogger.logger.debug(j({msg: "Making MFA OOB request"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-otp")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password_mfa grant"
            };
        }
        if (!this.oidcConfig?.issuer) {
            return {error: "server_error", error_description: "Cannot get issuer"};
        }

        const url = this.oidcConfig.issuer + 
            (this.oidcConfig.issuer.endsWith("/") ? "" : "/") + "mfa/challenge";
        const resp = await this.post(url, {
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            challenge_type: "oob",
            mfa_token: mfaToken,
            authenticator_id: authenticatorId,
        }, this.authServerHeaders);
        if (resp.challenge_type != "oob" || !resp.oob_code || !resp.binding_method) {
            return {error: resp.error??"server_error", error_description: resp.error_description??"Invalid OOB challenge response"};
        }

        return {
            challenge_type: resp.challenge_type,
            oob_code: resp.oob_code,
            binding_method: resp.binding_method,
            error: resp.error,
            error_description: resp.error_description,
        }

    }

    /**
     * Completes the Password MFA OTP flow.
     * 
     * Does not throw exceptions.
     * 
     * @param mfaToken the MFA token that was returned by the authorization
     *        server in the response from the Password Flow.
     * @param oobCode the code entered by the user
     * @returns an {@link OAuthTokenResponse} object, which may contain
     *          an error instead of the response fields.
     */
    async mfaOobComplete(mfaToken: string,
        oobCode: string,
        bindingCode: string,
        scope?: string) : Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Completing MFA OOB request"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported
            .includes("http://auth0.com/oauth/grant-type/mfa-oob")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support password_mfa grant"
            };
        }
        if (!this.oidcConfig?.issuer) {
            return {error: "server_error", error_description: "Cannot get issuer"};
        }

        const url = this.oidcConfig.token_endpoint;
        const resp = await this.post(url, {
            grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            challenge_type: "otp",
            mfa_token: mfaToken,
            oob_code: oobCode,
            binding_code: bindingCode,
            scope: scope,
        }, this.authServerHeaders);
        if (resp.error) {
            return {
                error: resp.error,
                error_description: resp.error_description,
            }
        }
        if (resp.id_token) {
            const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
            if (userInfo.error) {
                return userInfo;
            }
            resp.id_payload = userInfo.payload;
        }
        return {
            id_token: resp.id_token,
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            expires_in: "expires_in" in resp ? Number(resp.expires_in) : undefined,
            scope: resp.scope,
            token_type: resp.token_type,
        }

    }

    //////////////////////////////////////////////////////////////////////
    // Refresh Token Flow

    async refreshTokenFlow(refreshToken : string) : 
        //Promise<{[key:string]:any}> {
        Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Starting refresh token flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported.includes("refresh_token")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support refresh_token grant"
            };
        }
        if (!this.oidcConfig?.token_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get token endpoint"
            };
        }

        const url = this.oidcConfig.token_endpoint;

        let client_secret : string|undefined;
        client_secret = this.#client_secret;

        let params : {[key:string]:any} = {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: this.#client_id,
        }
        if (client_secret) params.client_secret = client_secret;
        try {
            let resp =  await this.post(url, params, this.authServerHeaders);
            if (resp.id_token) {
                const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
                if (userInfo.error) {
                    return userInfo;
                }
                resp.id_payload = userInfo.payload;
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    //////////////////////////////////////////////////////////////////////
    // Device Code Flow

    /**
     * Starts the Device Code Flow on the primary device (the one wanting an access token)
     * @param url The URl for the device_authorization endpoint, as it is not defined in the OIDC configuration
     * @param scope optional scope to request authorization for
     * @returns See {@link OAuthDeviceAuthorizationResponse}
     */
    async startDeviceCodeFlow(url : string, scope?: string) : Promise<OAuthDeviceAuthorizationResponse> {
        CrossauthLogger.logger.debug(j({msg: "Starting device code flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:device_code")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support device code grant"
            };
        }

        let params : {[key:string]:any} = {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
        }
        if (scope) params.scope = scope;
        try {
            let resp = await this.post(url, params, this.authServerHeaders);
            if (resp.id_token && !(await this.validateIdToken(resp.id_token))) {
                return {error: "access_denied", error_description: "Invalid ID token"}
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    /**
     * Polls the device endpoint to check if the device code flow has been
     * authorized by the user.
     * 
     * @param deviceCode the device code to poll
     * @returns See {@link OAuthDeviceResponse}
     */
    async pollDeviceCodeFlow(deviceCode : string) : Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Starting device code flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:device_code")) {
            return {
                error: "invalid_request",
                error_description: "Server does not support device code grant"
            };
        }
        if (!this.oidcConfig?.token_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get token endpoint"
            };
        }

        let params : {[key:string]:any} = {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            client_id: this.#client_id,
            client_secret: this.#client_secret,
            device_code: deviceCode,
        }
        try {
            const resp = await this.post(this.oidcConfig?.token_endpoint, params, this.authServerHeaders);
            if (resp.error) return resp;
            if (resp.id_token) {
                const userInfo = await this.getIdPayload(resp.id_token, resp.access_token);
                if (userInfo.error) {
                    return userInfo;
                }
                resp.id_payload = userInfo.payload;
            }
            return resp;
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    //////////////////////////////////////////////////////////////////
    // UserInfo

    async userInfoEndpoint(access_token : string) : Promise<{[key:string]:any}> {
        if (!this.oidcConfig?.userinfo_endpoint) {
            return {
                error: "server_error",
                error_description: "Cannot get token endpoint"
            };
        }
        const url = this.oidcConfig.userinfo_endpoint;

        const resp = await this.post(url, {}, {authorization: "Bearer " + access_token});
        return resp;
    }
    /**
     * Makes a POST request to the given URL using `fetch()`.
     * 
     * @param url the URL to fetch
     * @param params the body parameters, which are passed as JSON.
     * @returns the parsed JSON response as an object.
     * @throws any exception raised by `fetch()`
     */
    protected async post(url : string, params : {[key:string]:any}, headers : {[key:string]:any} = {}) : 
        Promise<{[key:string]:any}>{
        CrossauthLogger.logger.debug(j({
            msg: "Fetch POST",
            url: url,
            params: Object.keys(params)
        }));
        let options : {[key:string]:any} = {};
        if ( this.authServerCredentials) options.credentials = this.authServerCredentials;
        if ( this.authServerMode) options.mode = this.authServerMode;
        let body = "";
        let contentType = "";
        if (this.oauthPostType == "json") {
            body = JSON.stringify(params);
            contentType = "application/json";
        } else {
            body = "";
            for (let name in params) {
                if (body != "") body += "&";
                body += encodeURIComponent(name) + "=" + encodeURIComponent(params[name]);
            }
            contentType = "application/x-www-form-urlencoded";
        }
        if (this.oauthLogFetch) {
            CrossauthLogger.logger.debug(j({msg: "OAuth fetch", method: "POST", url: url, body: body}))
        }
        const resp = await fetch(url, {
            method: 'POST',
            ...options,
            headers: {
                'Accept': 'application/json',
                'Content-Type': contentType,
                ...headers,
            },
            body: body
        });
        const json = await resp.json();
        if (this.oauthLogFetch) {
            CrossauthLogger.logger.debug(j({msg: "OAuth fetch response", body: JSON.stringify(json)}))
        }
        return json;
    }

    /**
     * Makes a GET request to the given URL using `fetch()`.
     * 
     * @param url the URL to fetch
     * @param headers any headers to add to the request
     * @returns the parsed JSON response as an object.
     * @throws any exception raised by `fetch()`
     */
    protected async get(url : string, headers : {[key:string]:any} = {}) : 
        Promise<{[key:string]:any}|{[key:string]:any}[]>{
        CrossauthLogger.logger.debug(j({msg: "Fetch GET", url: url}));
        let options : {[key:string]:any} = {};
        if ( this.authServerCredentials) options.credentials = this.authServerCredentials;
        if ( this.authServerMode) options.mode = this.authServerMode;
        if (this.oauthLogFetch) {
            CrossauthLogger.logger.debug(j({msg: "OAuth fetch", method: "GET", url: url}))
        }
        const resp = await fetch(url, {
            method: 'GET',
            ...options,
            headers: {
                'Accept': 'application/json',
                ...headers,
            },
        });
        const json = await resp.json();
        if (this.oauthLogFetch) {
            CrossauthLogger.logger.debug(j({msg: "OAuth fetch response", body: JSON.stringify(json)}))
        }
        return json;
    }

    /**
     * Validates an OpenID ID token, returning undefined if it is invalid.
     * 
     * Does not raise exceptions.
     * 
     * @param token the token to validate.  To be valid, the signature must
     *        be valid and the `type` claim in the payload must be set to `id`.
     * @returns the parsed payload or undefined if the token is invalid.
     */
    async validateIdToken(token : string) : 
        Promise<{[key:string]:any}|undefined>{
        try {
            return await this.tokenConsumer.tokenAuthorized(token, "id");
        } catch (e) {
            return undefined;
        }
    }

    /**
     * Validates an access token, returning undefined if it is invalid.
     * 
     * Does not raise exceptions.
     * 
     * @param token the token to validate.  To be valid, the signature must
     *        be valid and the `type` claim in the payload must be set to `id`.
     * @returns the parsed payload or undefined if the token is invalid.
     */
    async validateAccessToken(token : string, checkAudience? : boolean) : 
        Promise<{[key:string]:any}|undefined>{
        try {
            return await this.tokenConsumer.tokenAuthorized(token, "access", checkAudience);
        } catch (e) {
            return undefined;
        }
    }

    /**
     * Validatesd a token using the token consumer.
     * 
     * @param idToken the token to validate
     * @returns the parsed JSON of the payload, or undefinedf if it is not
     * valid.
     */
    async idTokenAuthorized(idToken: string, checkAudience? : boolean) 
        : Promise<{[key:string]: any}|undefined> {
            try {
                return await this.tokenConsumer.tokenAuthorized(idToken, "id", checkAudience);
            } catch (e) {
                CrossauthLogger.logger.warn(j({err: e}));
                return undefined;
            }
        }

    getTokenPayload(token : string) : {[key:string] : any} {
        return jose.decodeJwt(token);
    }
}

/**
 * Fields that canb be returned by the `mfaAuthenticators` function call
 * if {@link OAuthClientBase}.
 * 
 * See Auth0's documentation for the password MFA flow.
 */
export interface MfaAuthenticatorResponse {
    authenticator_type: string,
    id : string,
    active: boolean,
    oob_channel? : string,
    name?: string,
}

export interface MfaAuthenticatorsResponse {
    authenticators?: MfaAuthenticatorResponse[],
    error?: string,
    error_description?: string,
}
