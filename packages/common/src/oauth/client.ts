import { CrossauthLogger, j } from '..';
import { CrossauthError, ErrorCode } from '..';
import { OpenIdConfiguration, DEFAULT_OIDCCONFIG } from '..';

export class OAuthFlows {
    static readonly All = "all";
    static readonly AuthorizationCode = "AuthorizationCode";
    static readonly AuthorizationCodeWithPKCE = "AuthorizationCodeWithPKCE";
    static readonly ClientCredentials = "ClientCredentials";

    static isValidFlow(flow : string) : boolean {
        return [OAuthFlows.AuthorizationCode,
                OAuthFlows.AuthorizationCodeWithPKCE,
                OAuthFlows.ClientCredentials].includes(flow);
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
            OAuthFlows.ClientCredentials]
    }
} 

export interface OAuthTokenResponse {
    access_token?: string,
    refresh_token? : string, 
    token_type?: string, 
    expires_in?: number,
    error? : string,
    error_description? : string,
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
    protected activeFlow : string = "";

    constructor({authServerBaseUri,
        clientId,
        clientSecret,
        redirectUri,
        codeChallengeMethod,
        stateLength,
        verifierLength,
    } : {
        authServerBaseUri : string,
        stateLength? : number,
        verifierLength? : number,
        clientId? : string,
        clientSecret? : string,
        redirectUri? : string,
        codeChallengeMethod? : "plain" | "S256"
    }) {
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
            const url = new URL("/.well-known/openid-configuration", this.authServerBaseUri);
            CrossauthLogger.logger.debug(j({msg: `Fetching OIDC config from ${url}`}))
            resp = await fetch(url);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
        }
        if (!resp || !resp.ok) {
            throw new CrossauthError(ErrorCode.server_error, "Couldn't get OIDC configuration");
        }
        this.oidcConfig = {...DEFAULT_OIDCCONFIG};
        try {
            const body = await resp.json();
            for (const [key, value] of Object.entries(body)) {
                this.oidcConfig[key] = value;
            }
            CrossauthLogger.logger.debug(j({msg: `OIDC Config ${JSON.stringify(this.oidcConfig)}`}));
        } catch (e) {
            throw new CrossauthError(ErrorCode.server_error, "Unrecognized response from OIDC configuration endpoint");
        }
    }

    protected abstract randomValue(length : number) : string;
    protected abstract sha256(plaintext :string) : string;

    protected async startAuthorizationCodeFlow(scope? : string, pkce : boolean=false) : Promise<string> {
        CrossauthLogger.logger.debug(j({msg: "Starting authorization code flow"}));
        if (!this.oidcConfig) await this.loadConfig();
        if (!this.oidcConfig?.response_types_supported.includes("code")
            || !this.oidcConfig?.response_modes_supported.includes("query")) {
            throw new CrossauthError(ErrorCode.invalid_request, "Server does not support authorization code flow");
        }
        if (!this.oidcConfig?.authorization_endpoint) {
            throw new CrossauthError(ErrorCode.server_error, "Cannot get authorize endpoint");
        }
        this.state = this.randomValue(this.stateLength);
        if (!this.clientId) throw new CrossauthError(ErrorCode.invalid_request, "Cannot make authorization code flow without client id");
        if (!this.redirectUri) throw new CrossauthError(ErrorCode.invalid_request, "Cannot make authorization code flow without redirect Uri");

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
            this.codeChallenge = this.codeChallengeMethod == "plain" ? this.codeVerifier : this.sha256(this.codeVerifier);
            url += "&code_challenge=" + this.codeChallenge;
            this.activeFlow = OAuthFlows.AuthorizationCodeWithPKCE;
        } else {
            this.activeFlow = OAuthFlows.AuthorizationCode;
        }

        return url;
    }

    protected async redirectEndpoint(code? : string, state? : string, error? : string, errorDescription? : string) : Promise<OAuthTokenResponse>{
        if (error || !code) {
            if (!error) error = "server_error";
            if (!errorDescription) errorDescription = "Unknown error";
            return {error, error_description: errorDescription};
        }
        if (this.state) {
            if (state != this.state) {
                return {error: ErrorCode[ErrorCode.access_denied], error_description: "State is not valid"};
            }
        }
        this.authzCode = code;    

        if (!this.oidcConfig?.token_endpoint) {
            throw new CrossauthError(ErrorCode.server_error, "Cannot get token endpoint");
        }
        const url = this.oidcConfig.token_endpoint;

        let grant_type : string;
        let clientSecret : string|undefined;
        if (this.activeFlow == OAuthFlows.AuthorizationCode || this.activeFlow == OAuthFlows.AuthorizationCodeWithPKCE) {
            grant_type = "authorization_code";
            clientSecret = this.clientSecret;
        } else {
            return {error: ErrorCode[ErrorCode.server_error], error_description: "Unsupported flow " + OAuthFlows.AuthorizationCode};
        }
        let params : {[key:string]:any} = {
            grant_type: grant_type,
            client_id: this.clientId,
            code: this.authzCode,
        }
        if (clientSecret) params.client_secret = clientSecret;
        if (this.activeFlow == OAuthFlows.AuthorizationCodeWithPKCE) params.code_verifier = this.codeVerifier;
        try {
            return this.post(url, params);
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            return {error: ErrorCode[ErrorCode.server_error], error_description: "Unable to get access token from server"};
        }
    }

    protected async post(url : string, params : {[key:string]:any}) : Promise<{[key:string]:any}>{
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
}