import { CrossauthLogger, j } from '..';
import { CrossauthError, ErrorCode } from '..';
import {
    OpenIdConfiguration,
    OAuthTokenConsumerBase,
    DEFAULT_OIDCCONFIG,
    type GrantType } from '..';

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
                return ["http://auth0.com/oauth/grant-type/mfa-otp"];
            case OAuthFlows.DeviceCode:
                return ["device_code"];
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
    token_type?: string, 
    expires_in?: number,
    error? : string,
    error_description? : string,
    scope?: string,
    mfa_token? : string,
}

/**
 * An abstract base class for OAuth clients.
 * 
 * Crossauth provides OAuth clients that work in the browser as well as in
 * Node.  This base class contains all the non-interpreter specific 
 * functionality.  What is missing is the cryptography which is included
 * in derived Node-only and Browser-only classes.  
 * See {@link @crossauth/backend!OAuthClientBackend}.
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
    protected clientId : string|undefined;
    protected clientSecret : string|undefined;
    protected codeChallenge : string|undefined;
    protected codeChallengeMethod : "plain" | "S256" = "S256";
    protected codeVerifier : string|undefined;
    protected verifierLength = 32;
    protected redirectUri : string|undefined;
    protected state = "";
    protected stateLength = 32;
    protected authzCode : string = "";
    protected oidcConfig : (OpenIdConfiguration&{[key:string]:any})|undefined;
    protected tokenConsumer : OAuthTokenConsumerBase;
    protected fetchCredentials : "same-origin"|"include"|undefined = undefined;
    protected authServerHeaders : {[key:string]:string} = {};

    /**
     * Constructor.
     * 
     * @param options options:
     *      - `authServerBaseUrl` the base URI for OAuth calls.  This is
     *        the value in the isser field of a JWT.  The client will
     *        reject any JWTs that are not from this issuer.
     *      - `clientId` the client ID for this client.
     *      - `redriectUri` when making OAuth calls, this value is put
     *        in the redirectUri field.
     *      - `number` of characters (before base64-url-encoding) for generating
     *        state values in OAuth calls.
     *      - `verifierLength` of characters (before base64-url-encoding) for
     *        generating PKCE values in OAuth calls.
     *      - `tokenConsumer` to keep this class independent of frontend 
     *        and backend specific funtionality (eg classes not available
     *        in browsers), the token consumer, which determines if a token
     *        is valid or not, is abstracted out.
     */
    constructor({authServerBaseUrl,
        clientId,
        clientSecret,
        redirectUri,
        codeChallengeMethod,
        stateLength,
        verifierLength,
        tokenConsumer,
        fetchCredentials,
    } : {
        authServerBaseUrl : string,
        stateLength? : number,
        verifierLength? : number,
        clientId? : string,
        clientSecret? : string,
        redirectUri? : string,
        codeChallengeMethod? : "plain" | "S256",
        tokenConsumer : OAuthTokenConsumerBase,
        fetchCredentials? : "same-origin"|"include",
    }) {
        this.tokenConsumer = tokenConsumer;
        this.authServerBaseUrl = authServerBaseUrl;
        if (verifierLength) this.verifierLength = verifierLength;
        if (stateLength) this.stateLength = stateLength;
        if (clientId) this.clientId = clientId;
        if (clientSecret) this.clientSecret = clientSecret;
        if (redirectUri) this.redirectUri = redirectUri;
        if (codeChallengeMethod) this.codeChallengeMethod = codeChallengeMethod;
        this.authServerBaseUrl = authServerBaseUrl;
        if (fetchCredentials) this.fetchCredentials = fetchCredentials;

    }

    /**
     * Any headers added here will be applied to all requests to the
     * authorization server.
     * 
     * @param header the header name eg `Access-Control-Allow-Origin`
     * @param value the header value
     */
    addAuthServerHeader(header : string, value : string) {
        this.authServerHeaders[header] = value;
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
            const url = new URL("/.well-known/openid-configuration",
                this.authServerBaseUrl);
            CrossauthLogger.logger.debug(j({msg: `Fetching OIDC config from ${url}`}))
            resp = await fetch(url, {headers: this.authServerHeaders});
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
        }
        if (!resp || !resp.ok) {
            throw new CrossauthError(ErrorCode.Connection, 
                "Couldn't get OIDC configuration");
        }
        this.oidcConfig = {...DEFAULT_OIDCCONFIG};
        try {
            const body = await resp.json();
            for (const [key, value] of Object.entries(body)) {
                this.oidcConfig[key] = value;
            }
            CrossauthLogger.logger.debug(j({msg: `OIDC Config ${JSON.stringify(this.oidcConfig)}`}));
        } catch (e) {
            throw new CrossauthError(ErrorCode.Connection, 
                "Unrecognized response from OIDC configuration endpoint");
        }
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
    async startAuthorizationCodeFlow(scope?: string,
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
        this.state = this.randomValue(this.stateLength);
        if (!this.clientId) return {
            error: "invalid_request",
            error_description: "Cannot make authorization code flow without client id"
        }; 
        if (!this.redirectUri) return {
            error: "invalid_request",
            error_description: "Cannot make authorization code flow without Redirect Uri"
        }; 

        const base = this.oidcConfig.authorization_endpoint;
        let url = base 
            + "?response_type=code"
            + "&client_id=" + encodeURIComponent(this.clientId)
            + "&state=" + encodeURIComponent(this.state)
            + "&redirect_uri=" + encodeURIComponent(this.redirectUri);

        if (scope) {
            url += "&scope=" + encodeURIComponent(scope);
        }

        if (pkce) {
            this.codeVerifier = this.randomValue(this.verifierLength);
            this.codeChallenge = 
                this.codeChallengeMethod == "plain" ? 
                this.codeVerifier : await this.sha256(this.codeVerifier);
            url += "&code_challenge=" + this.codeChallenge;
        }

        return {url: url};
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
    protected async redirectEndpoint(code?: string,
        state?: string,
        error?: string,
        errorDescription?: string) : Promise<OAuthTokenResponse>{
        if (error || !code) {
            if (!error) error = "server_error";
            if (!errorDescription) errorDescription = "Unknown error";
            return {error, error_description: errorDescription};
        }
        if (this.state) {
            if (state != this.state) {
                return {error: "access_denied", error_description: "State is not valid"};
            }
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
        let clientSecret : string|undefined;
        grant_type = "authorization_code";
        clientSecret = this.clientSecret;
        let params : {[key:string]:any} = {
            grant_type: grant_type,
            client_id: this.clientId,
            code: this.authzCode,
        }
        if (clientSecret) params.client_secret = clientSecret;
        params.code_verifier = this.codeVerifier;
        try {
            return this.post(url, params, this.authServerHeaders);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Unable to get access token from server"
            };
        }
    }

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
        if (!this.clientId) return {
            error: "invalid_request",
            error_description: "Cannot make client credentials flow without client id"
        }; 
        if (!this.clientSecret) return {
            error: "invalid_request",
            error_description: "Cannot make client credentials flow without client secret"
        }; 

        const url = this.oidcConfig.token_endpoint;

        let params : {[key:string]:any} = {
            grant_type: "client_credentials",
            client_id: this.clientId,
            client_secret: this.clientSecret,
        }
        if (scope) params.scope = scope;
        try {
            return await this.post(url, params, this.authServerHeaders);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

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
            client_id: this.clientId,
            client_secret: this.clientSecret,
            username : username,
            password : password,
        }
        if (scope) params.scope = scope;
        try {
            return await this.post(url, params, this.authServerHeaders);
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
            .includes("http://auth0.com/oauth/grant-type/mfa-otp")) {
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
        CrossauthLogger.logger.debug(j({msg: "Getting valid MFA authenticators"}));
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
            client_id: this.clientId,
            client_secret: this.clientSecret,
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
        otp: string) : 
        Promise<{
        access_token? : string, 
        refresh_token? : string, 
        id_token?: string, 
        expires_in? : number, 
        scope? : string, 
        token_type?: string, 
        error? : string, 
        error_description? : string}> {
        CrossauthLogger.logger.debug(j({msg: "Getting valid MFA authenticators"}));
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
            client_id: this.clientId,
            client_secret: this.clientSecret,
            challenge_type: "otp",
            mfa_token: mfaToken,
            otp: otp,
        }, this.authServerHeaders);
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
        CrossauthLogger.logger.debug(j({msg: "Getting valid MFA authenticators"}));
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
            client_id: this.clientId,
            client_secret: this.clientSecret,
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
        bindingCode: string) : Promise<OAuthTokenResponse> {
        CrossauthLogger.logger.debug(j({msg: "Getting valid MFA authenticators"}));
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

        const url = this.oidcConfig.token_endpoint;
        const resp = await this.post(url, {
            grant_type: "http://auth0.com/oauth/grant-type/mfa-oob",
            client_id: this.clientId,
            client_secret: this.clientSecret,
            challenge_type: "otp",
            mfa_token: mfaToken,
            oob_code: oobCode,
            binding_code: bindingCode,
        }, this.authServerHeaders);
        return {
            id_token: resp.id_token,
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            expires_in: Number(resp.expires_in),
            scope: resp.scope,
            token_type: resp.token_type,
            error: resp.error,
            error_description: resp.error_description,
        }

    }

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

        let clientSecret : string|undefined;
        clientSecret = this.clientSecret;

        let params : {[key:string]:any} = {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: this.clientId,
        }
        if (clientSecret) params.client_secret = clientSecret;
        try {
            return await this.post(url, params, this.authServerHeaders);
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
        const options = this.fetchCredentials ? {credentials: this.fetchCredentials} : {};
        const resp = await fetch(url, {
            method: 'POST',
            ...options,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                ...headers,
            },
            body: JSON.stringify(params)
        });
        return await resp.json();
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
        const options = this.fetchCredentials ? {credentials: this.fetchCredentials} : {};
        const resp = await fetch(url, {
            method: 'GET',
            ...options,
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                ...headers,
            },
        });
        return await resp.json();
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
     * Validatesd a token using the token consumer.
     * 
     * @param idToken the token to validate
     * @returns the parsed JSON of the payload, or undefinedf if it is not
     * valid.
     */
    async idTokenAuthorized(idToken: string) 
        : Promise<{[key:string]: any}|undefined> {
            try {
                return await this.tokenConsumer.tokenAuthorized(idToken, "id");
            } catch (e) {
                CrossauthLogger.logger.warn(j({err: e}));
                return undefined;
            }
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