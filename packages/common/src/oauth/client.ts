import { CrossauthLogger, j } from '..';
import { CrossauthError, ErrorCode } from '..';
import {
    OpenIdConfiguration,
    OAuthTokenConsumerBase,
    DEFAULT_OIDCCONFIG,
    type GrantType } from '..';

export class OAuthFlows {
    static readonly All = "all";
    static readonly AuthorizationCode = "AuthorizationCode";
    static readonly AuthorizationCodeWithPKCE = "AuthorizationCodeWithPKCE";
    static readonly ClientCredentials = "ClientCredentials";
    static readonly RefreshToken = "RefreshToken";
    static readonly DeviceCode = "DeviceCode";
    static readonly Password = "Password";
    static readonly PasswordMfa = "PasswordMfa";
    static readonly OidcAuthorizationCode = "OidcAuthorizationCode";

    static isValidFlow(flow : string) : boolean {
        return OAuthFlows.allFlows().includes(flow);
    }

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

export abstract class OAuthClientBase {
    protected authServerBaseUri = "";
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

    constructor({authServerBaseUri,
        clientId,
        clientSecret,
        redirectUri,
        codeChallengeMethod,
        stateLength,
        verifierLength,
        tokenConsumer,
    } : {
        authServerBaseUri : string,
        stateLength? : number,
        verifierLength? : number,
        clientId? : string,
        clientSecret? : string,
        redirectUri? : string,
        codeChallengeMethod? : "plain" | "S256",
        tokenConsumer : OAuthTokenConsumerBase,
    }) {
        this.tokenConsumer = tokenConsumer;
        this.authServerBaseUri = authServerBaseUri;
        if (verifierLength) this.verifierLength = verifierLength;
        if (stateLength) this.stateLength = stateLength;
        if (clientId) this.clientId = clientId;
        if (clientSecret) this.clientSecret = clientSecret;
        if (redirectUri) this.redirectUri = redirectUri;
        if (codeChallengeMethod) this.codeChallengeMethod = codeChallengeMethod;
        this.authServerBaseUri = authServerBaseUri;
    }

    async loadConfig(oidcConfig? : OpenIdConfiguration) {
        if (oidcConfig) {
            CrossauthLogger.logger.debug(j({msg: "Reading OIDC config locally"}))
            this.oidcConfig = oidcConfig;
            return;
        }

        let resp : Response|undefined = undefined;
        try {
            const url = new URL("/.well-known/openid-configuration",
                this.authServerBaseUri);
            CrossauthLogger.logger.debug(j({msg: `Fetching OIDC config from ${url}`}))
            resp = await fetch(url);
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

    protected abstract randomValue(length : number) : string;
    protected abstract sha256(plaintext :string) : string;

    protected async startAuthorizationCodeFlow(scope?: string,
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
                this.codeVerifier : this.sha256(this.codeVerifier);
            url += "&code_challenge=" + this.codeChallenge;
        }

        return {url: url};
    }

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
            return this.post(url, params);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Unable to get access token from server"
            };
        }
    }

    protected async clientCredentialsFlow(scope? : string) : Promise<{[key:string]:any}> {
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
            return await this.post(url, params);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

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
            return await this.post(url, params);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }


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
            await this.get(url, {'authorization': 'Bearer ' + mfaToken});
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
        });
        if (resp.challenge_type != "otp") {
            return {
                error: resp.error ?? "server_error",
                error_description: resp.error_description ?? "Invalid OTP challenge response"
            };
        }

        return resp;
    }

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
        });
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
        });
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
        });
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

    protected async refreshTokenFlow(refreshToken : string) : 
        Promise<{[key:string]:any}> {
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

        let params : {[key:string]:any} = {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
        }
        try {
            return await this.post(url, params);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {
                error: "server_error",
                error_description: "Error connecting to authorization server"
            };
        }
        //return {url: url, params: params};
    }

    protected async post(url : string, params : {[key:string]:any}) : 
        Promise<{[key:string]:any}>{
        CrossauthLogger.logger.debug(j({
            msg: "Fetch POST",
            url: url,
            params: Object.keys(params)
        }));
        const resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(params)
        });
        return await resp.json();
    }

    protected async get(url : string, headers : {[key:string]:any}) : 
        Promise<{[key:string]:any}|{[key:string]:any}[]>{
        CrossauthLogger.logger.debug(j({msg: "Fetch GET", url: url}));
        const resp = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                ...headers,
            },
        });
        return await resp.json();
    }

    async validateIdToken(token : string) : 
        Promise<{[key:string]:any}|undefined>{
        try {
            return await this.tokenConsumer.tokenAuthorized(token, "id");
        } catch (e) {
            return undefined;
        }
    }

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

export interface MfaAuthenticatorResponse {
    authenticator_type: string,
    id : string,
    active: boolean,
    oob_channel? : string,
    name?: string,
}