// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import {
    OAuthClientStorage,
    KeyStorage,
    OAuthAuthorizationServer,
    setParameter,
    ParamType,
    Authenticator,
    Crypto, 
    OAuthClientManager,
    DoubleSubmitCsrfToken,
    toCookieSerializeOptions,
 } from '@crossauth/backend';

import type {
    OAuthAuthorizationServerOptions,
    DoubleSubmitCsrfTokenOptions,
    Cookie,
    UpstreamClientOptions,
    OAuthClientOptions,
 } from '@crossauth/backend';
import { SvelteKitServer } from './sveltekitserver';
import {
    CrossauthError,
    CrossauthLogger,
    type OpenIdConfiguration,
    j,
    OAuthFlows,
    ErrorCode,
    type User,
    type MfaAuthenticatorResponse,
    type OAuthClient } from '@crossauth/common';
import { json } from '@sveltejs/kit';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';
import { type CookieSerializeOptions } from 'cookie';
import { OAuthClientBackend } from '@crossauth/backend';
import { type MaybePromise } from './tests/sveltemocks';

const DEFAULT_UPSTREAM_SESSION_DATA_NAME = "upstreamoauth";

//////////////////////////////////////////////////////////////////////////////
// ENDPOINT INTERFACES

/**
 * Query parameters for the `authorize` request.
 */
export interface AuthorizeQueryType {
    response_type : string,
    client_id : string,
    redirect_uri : string,
    scope? : string,
    state: string,
    code_challenge? : string,
    code_challenge_method? : string,
    next? : string,
}

export interface ReturnBase {
    ok: boolean,
    error? : string,
    error_description? : string,
};

/**
 * Return type for {@link SvelteKitUserEndpoints.verifyEmail}
 * {@link SvelteKitUserEndpoints.verifyEmailTokenEndpoint} action. 
 * 
 * See class documentation for {@link SvelteKitUserEndpoints} for more details.
 */
export interface AuthorizePageData extends ReturnBase {
    authorized?: {
        code : string,
        state : string,    
    },
    authorizationNeeded?: {
        user: User,
        response_type: string,
        client_id : string,
        client_name : string,
        redirect_uri: string,
        scope?: string,
        scopes?: string[],
        state: string,
        code_challenge?: string,
        code_challenge_method?: string,
        csrfToken?: string,
    },
    user?: User,
    csrfToken? : string,
};


export interface AuthorizeActionData extends ReturnBase {
    formData? : {[key:string]:string},
}

export interface DevicePageData extends ReturnBase {
    authorizationNeeded?: {
        user: User,
        client_id : string,
        client_name : string,
        scope?: string,
        scopes?: string[],
        csrfToken?: string,
    },
    completed: boolean,
    retryAllowed?: boolean,
    user?: User,
    csrfToken? : string,
    ok: boolean,
    error? : string,
    error_description? : string,
    user_code?: string,
};


export interface DeviceActionData extends ReturnBase {
    authorizationNeeded?: {
        user: User,
        client_id : string,
        client_name : string,
        scope?: string,
        scopes?: string[],
        csrfToken?: string,
    },
    completed: boolean,
    retryAllowed: boolean,
    user?: User,
    csrfToken? : string,
    ok: boolean,
    error? : string,
    error_description? : string,
    user_code?: string,
}

/**
 * The body parameters for the `mfa/challenge` endpoint.  
 */
export interface MfaChallengeBodyType {
    client_id : string,
    client_secret?: string,
    challenge_type: string,
    mfa_token : string,
    authenticator_id : string,
}

export interface MfaChallengeReturn {
    challenge_type?: string,
    oob_code? : string,
    binding_method? : string,
    error? : string,
    error_description? : string,
}

//////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link SvelteKitAuthorizationServer}
 */
export interface SvelteKitAuthorizationServerOptions 
    extends OAuthAuthorizationServerOptions {

    /**
     * The login URL (provided by {@link SvelteKitSessionServer}). Default `/login`
     */
    loginUrl? : string,

    /**
     * How to send the refresh token.
     *   - `json` sent in the JSON response as per the OAuth specification
     *   - `cookie` sent as a cookie called `refreshTokenCookieName`.
     *   - `both` both of the above
     * Default `json`
     */
    refreshTokenType? : "json" | "cookie" | "both",

    /**
     * If `refreshTokenType` is `cookie` or `both`, this will be the cookie
     * name.  Default `CROSSAUTH_REFRESH_TOKEN`
     */
    refreshTokenCookieName? : string,

    /**
     * Domain to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieDomain? : string | undefined;

    /**
     * Whether to set `httpOnly` when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieHttpOnly? : boolean;

    /**
     * Path to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`.
     * 
     * Default "/".
     */
    refreshTokenCookiePath? : string;

    /**
     * Whether to set the `secure` flag when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieSecure? : boolean;

    /**
     * SameSite value to set when sending a refresh token cookie.
     * Only used if `refreshTokenType` is not `json`
     */
    refreshTokenCookieSameSite? : boolean | "lax" | "strict" | "none" | undefined;

    /** options for csrf cookie manager */
    doubleSubmitCookieOptions? : DoubleSubmitCsrfTokenOptions,

    /**
     * Set this to the route where you create your authorize endpoint.
     * 
     * The default is '/oauth/authozize`
     */
    authorizeEndpointUrl? : string,

    /**
     * Set this to the route where you create your authorize endpoint.
     * 
     * The default is '/oauth/token`
     */
    tokenEndpointUrl? : string,

    /**
     * Set this to the route where you create your jwks endpoint.
     * 
     * The default is '/oauth/jwks`
     */
    jwksEndpoint? : string,

    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,

    /**
     * This is used when there is an upstream client to save the tokens.
     * Default `oauth`.
     */
    sessionDataName? : string,
}

///////////////////////////////////////////////////////////////////////////////
// CLASS

/**
 * This class implements an OAuth authorization server, serving endpoints
 * with SvelteKit.
 * 
 * You shouldn't have to instantiate this directly.  It is instantiated
 * by {@link SvelteKitServer} if you enable the authorization server there.
 * 
 * **Endpoints**
 * 
 * | Name                        | Description                                                | PageData (returned by load) or JSON returned by get/post                     | ActionData (return by actions)                                   | Form fields expected by actions or post/get input data          | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | baseEndpoint                | This PageData is returned by all endpoints' load function. | - `user` logged in {@link @crossauth/common!User}                            | *Not provided*                                                   |                                                                 |  
 * |                             |                                                            | - `csrfToken` CSRF token if enabled                                          |                                                                  |                                                                 |                                                                         | loginPage                | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | oidcConfigurationEndpoint   | Use this as your `.well-known/openid-configuration`.       | `get`:                                                                       |                                                                  |                                                                 | 
 * |                             |                                                            |   - see {@link @crossauth/backend!OAuthAuthorizationServer.oidcConfiguration} |                                                                 |                                                                 | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | jwksGetEndpoint             | Use this as your `jwks` endpoint.                          | `get`:                                                                       |                                                                  |                                                                 |  
 * |                             |                                                            |   - see {@link @crossauth/backend!OAuthAuthorizationServer.jwks}             |                                                                  |                                                                 |  
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | getCsrfTokenEndpoint        | Sends a CSRF token for use when refresh token is a cookie  | `get`:                                                                       |                                                                  |                                                                 | 
 * |                             |                                                            |   - `ok` (true or false)                                                     |                                                                  |                                                                 |
 * |                             |                                                            |   - `csrfToken`                                                              |                                                                  |                                                                 | 
 * |                             |                                                            |   - `error`                                                                  |                                                                  |                                                                 | 
 * |                             |                                                            |   - `error_description`                                                      |                                                                  |                                                                 | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | authorizeEndpoint           | The OAuth `authorize` endpoint                             | `load`:                                                                      | `default`:                                                       | `authorized` true if the user clicks authorized                 | 
 * |                             |                                                            |   - `succcess` (true or false)                                               |   - `ok`: true or false                                     | `response_type` OAuth response type (take from PageData)        | 
 * |                             |                                                            |   - `authorizationNeeded`:                                                   |   - `formData`: fata submitted from in the form                  | `client_id` take from PageData                                  |  
 * |                             |                                                            |     - `user`: the user object                                                |   - `error` an OAuth error type                                  | `redirect_uri` take from PageData                               |   
 * |                             |                                                            |     - `response_type`: OAuth response type                                   |   - `error_description` text error description                   | `scope` take from PageData                                      |  
 * |                             |                                                            |     - `client_id`:                                                           |                                                                  | `state` take from PageData                                      | 
 * |                             |                                                            |     - `client_name`:                                                         |                                                                  | `code_challenge` take from PageData                             | 
 * |                             |                                                            |     - `redirect_uri`:                                                        |                                                                  | `code_challenge_method` take from PageData                      | 
 * |                             |                                                            |     - `scope`: as a string                                                   |                                                                  |                                                                 | 
 * |                             |                                                            |     - `scopes`: as an array                                                  |                                                                  |                                                                 |
 * |                             |                                                            |     - `state`:                                                               |                                                                  |                                                                 | 
 * |                             |                                                            |     - `code_challenge`:                                                      |                                                                  |                                                                 |  
 * |                             |                                                            |     - `code_challenge_method`:                                               |                                                                  |                                                                 |  
 * |                             |                                                            |     - `csrfToken`:                                                           |                                                                  |                                                                 |  
 * |                             |                                                            |   - `error`                                                                  |                                                                  |                                                                 |  
 * |                             |                                                            |   - `error_description`                                                      |                                                                  |                                                                 |  
 * |                             |                                                            |   See OAuth definition for more detials.                                     |                                                                  |                                                                 |  
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | tokenEndpoint               | The OAuth `token` endpoint                                 | `post`:                                                                      |                                                                  | See OAuth definition of `token` endpoint                        | 
 * |                             |                                                            |   - See OAuth definition of `token` endpoint                                 |                                                                  |                                                                 |  
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | mfaAuthenticatorsEndpoint   | For the Auth0 Password MFA authenticators                  | `get`:                                                                       |                                                                  | See OAuth definition of `token` endpoint                        | 
 * |                             |                                                            |   - See Auth0 Password MFA documentation                                     |                                                                  |                                                                 | 
 * |                             |                                                            | `post`:                                                                      |                                                                  |                                                                 | 
 * |                             |                                                            |   - See Auth0 Password MFA documentation                                     |                                                                  | See OAuth definition of `token` endpoint                        |  
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | mfaChallengeEndpoint        | For the Auth0 Password MFA challenge                       | `post`:                                                                      |                                                                  | See OAuth definition of `token` endpoint                        |
 * |                             |                                                            |   - See Auth0 Password MFA documentation                                     |                                                                  |                                                                 | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | deviceAuthorizationEndpoint | Starts the device flow (for the device)                    | `post`:                                                                      |                                                                  |  `client_id` client ID                                          |
 * |                             |                                                            |   - `ok` true or false                                                       |                                                                  |  `client_secret` if the client is confidential                  | 
 * |                             |                                                            |   - `error` if there was an error                                            |                                                                  |  `scope` optional                                               | 
 * |                             |                                                            |   - `error_description` if there was an error                                |                                                                  |                                                                 | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * | deviceEndpoint              | Device flow - authorization endpoint on other device       | `load`:                                                                      | `authorize`: to authorize scopes (call after `userCode`)         | `user_code` query param for GET, form field for POST. Optional  |
 * |                             |                                                            |   See {@link DevicePageData}                                                 |    See {@link DeviceActionData}                                    | If not provided, user will be prompted                          | 
 * |                             |                                                            |                                                                              | `userCode` to submit the user code                               | `authorize`: `client_id`, `user_code`, `authorized`             | 
 * | --------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------- | 
 * 
 */
export class SvelteKitAuthorizationServer {

    /** The underlying framework-independent authorization server */
    readonly authServer : OAuthAuthorizationServer;
    private svelteKitServer : SvelteKitServer;
    private loginUrl : string = "/login";
    private clientStorage : OAuthClientStorage;

    // Refresh token cookie functionality
    private refreshTokenType : "json"|"cookie"|"both" = "json";
    private refreshTokenCookieName : string = "CROSSAUTH_REFRESH_TOKEN";
    private refreshTokenCookieDomain : string | undefined = undefined;
    private refreshTokenCookieHttpOnly : boolean = false;
    private refreshTokenCookiePath : string = "/";
    private refreshTokenCookieSecure : boolean = true;
    private refreshTokenCookieSameSite : boolean | "lax" | "strict" | "none" | undefined = "strict";

    private csrfTokens : DoubleSubmitCsrfToken | undefined;

    private authorizeEndpointUrl = "/oauth/authorize";
    private tokenEndpointUrl = "/oauth/token";
    private jwksEndpointUrl = "/oauth/jwks";
    
    readonly redirect: any;
    readonly error: any;
    private sessionDataName = "oauth";

    /**
     * Constructor
     * @param svelteKitServer the SvelteKit server this belongs to
     * @param clientStorage where OAuth clients are stored
     * @param keyStorage where refresh tokens, authorization cods, etc are temporarily stored
     * @param authenticators The authenticators (factor1 and factor2) to enable 
     *        for the password flow
     * @param options see {@link SvelteKitAuthorizationServerOptions}
     */
    constructor(
        svelteKitServer : SvelteKitServer,
        clientStorage : OAuthClientStorage, 
        keyStorage : KeyStorage,
        authenticators? : {[key:string]: Authenticator},
        options : SvelteKitAuthorizationServerOptions = {}) {

        this.svelteKitServer = svelteKitServer;
        this.clientStorage = clientStorage;
        if (options.redirect) this.redirect = options.redirect;
        if (options.error) this.error = options.error;

        this.authServer =
            new OAuthAuthorizationServer(this.clientStorage,
                keyStorage,
                authenticators,
                options);

        let server = svelteKitServer;

        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("refreshTokenType", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_TYPE");
        setParameter("refreshTokenCookieName", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_NAME");
        setParameter("refreshTokenCookieDomain", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_DOMAIN");
        setParameter("refreshTokenCookieHttpOnly", ParamType.Boolean, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_HTTPONLY");
        setParameter("refreshTokenCookiePath", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_PATH");
        setParameter("refreshTokenCookieSecure", ParamType.Boolean, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_SECURE");
        setParameter("refreshTokenCookieSameSite", ParamType.String, this, options, "OAUTH_REFRESH_TOKEN_COOKIE_SAMESITE");
        setParameter("authorizeEndpointUrl", ParamType.String, this, options, "OAUTH_AUTHORIZE_ENDPOINT");
        setParameter("tokenEndpointUrl", ParamType.String, this, options, "OAUTH_TOKEN_ENDPOINT");
        setParameter("jwksEndpointUrl", ParamType.String, this, options, "OAUTH_JWKS_ENDPOINT");
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");

        if (this.refreshTokenType != "json") {
            if (this.svelteKitServer.sessionServer?.enableCsrfProtection == true) {
                this.csrfTokens = this.svelteKitServer.sessionServer.sessionManager.csrfTokens;
            } else {
                this.csrfTokens = new DoubleSubmitCsrfToken(options.doubleSubmitCookieOptions);
            }
        }
    }

    /**
     * Returns this server's OIDC configuration.  Just wraps
     * {@link @crossauth/backend!OAuthAuthorizationServer.oidcConfiguration}
     * @returns An {@link @crossauth/common!OpenIdConfiguration} object
     */
    oidcConfiguration() : OpenIdConfiguration {
        return this.authServer.oidcConfiguration({
                authorizeEndpoint: this.authorizeEndpointUrl, 
                tokenEndpoint: this.tokenEndpointUrl, 
                jwksUri: this.jwksEndpointUrl, 
                additionalClaims: []});
    };

    /**
     * Either returns an error or redirects with throw
     */
    private async authorize(event: RequestEvent,
        authorized: boolean, {
            responseType,
            client_id,
            redirect_uri,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod,
        } : {
            responseType : string,
            client_id : string,
            redirect_uri : string,
            scope? : string,
            state : string,
            codeChallenge? : string,
            codeChallengeMethod?: string,
        }) : Promise<ReturnBase> {
        let error : string|undefined;
        let errorDescription : string|undefined;
        let code : string|undefined;

        // Create an authorizatin code
        if (authorized) {
            const resp = await this.authServer.authorizeGetEndpoint({
                responseType,
                client_id,
                redirect_uri,
                scope,
                state,
                codeChallenge,
                codeChallengeMethod,
                user: event.locals.user,
            });
            code = resp.code;
            error = resp.error;
            errorDescription = resp.error_description;

            // couldn't create an authorization code
            if (error || !code) {
                const ce = CrossauthError.fromOAuthError(error??"server_error", 
                    errorDescription??"Neither code nor error received")
                CrossauthLogger.logger.error(j({cerr: ce}));
                return {
                    ok: false,
                    error,
                    error_description: errorDescription,
                }
            }

            throw this.redirect(302, this.authServer.redirect_uri(
                redirect_uri,
                code,
                state
            ));

        } else {

            // resource owner did not grant access
            const ce = new CrossauthError(ErrorCode.Unauthorized,  
                "You have not granted access");
                CrossauthLogger.logger.debug(j({err: ce}));
                CrossauthLogger.logger.error(j({cerr: ce}));
                        CrossauthLogger.logger.error(j({
                msg: errorDescription,
                errorCode: ce.code,
                errorCodeName: ce.codeName
            }));
            try {
                OAuthClientManager.validateUri(redirect_uri);
                throw this.redirect(302, redirect_uri + "?error=access_denied&error_description="+encodeURIComponent("Access was not granted")); 
            } catch (e) {
                if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                CrossauthLogger.logger.error(j({
                    msg: `Couldn't send error message ${ce.codeName} to ${redirect_uri}}`}));
                return {
                    ok: false,
                    error: "server_error",
                    error_description: "Redirect Uri is not valid"
                };
            }
        }
    }

    /**
     * Creates and returns a signed CSRF token based on the session ID
     * 
     * This is for the situation when the refresh token is sent as a cookie.
     * When this happens, we need CSRF protection on it.
     * 
     * @returns a CSRF cookie and value to put in the form or CSRF header
     */
    private async createCsrfToken() : 
        Promise<{csrfCookie : Cookie, csrfFormOrHeaderValue : string}> {
        if (!this.csrfTokens) throw new CrossauthError(ErrorCode.Configuration, "CSRF tokens not enabled");
        this.csrfTokens.makeCsrfCookie(this.csrfTokens.createCsrfToken());
        const csrfToken = this.csrfTokens.createCsrfToken();
        const csrfFormOrHeaderValue = this.csrfTokens.makeCsrfFormOrHeaderToken(csrfToken);
        const csrfCookie = this.csrfTokens.makeCsrfCookie(csrfToken);
        return {
            csrfCookie,
            csrfFormOrHeaderValue,
        }
    }

    private setRefreshTokenCookie(event : RequestEvent, token : string, expiresIn : number|undefined) {
        if (!this.refreshTokenCookieName) return;
        let expiresAt = expiresIn ? new Date(Date.now() + expiresIn*1000).toUTCString() : undefined;
        let cookieParams : CookieSerializeOptions & {path: string} = {
            path: this.refreshTokenCookiePath ?? "/",
        }
        if (expiresAt) cookieParams.expires = new Date(expiresAt);
        if (this.refreshTokenCookieSameSite) cookieParams.sameSite = this.refreshTokenCookieSameSite;
        if (this.refreshTokenCookieDomain) cookieParams.domain = this.refreshTokenCookieDomain;
        if (this.refreshTokenCookieHttpOnly == true) cookieParams.httpOnly = true;
        if (this.refreshTokenCookieSecure == true) cookieParams.secure = true;
        
        event.cookies.set(
            this.refreshTokenCookieName, 
            token, cookieParams
        );
    }

    private requireGetParam(url: URL, name : string) : ReturnBase | undefined {
        const val = url.searchParams.get(name);
        if (!val) return {
            ok: false,
            error: "invalid_request",
            error_description: name + " is required"
        };
        return undefined;
    }

    private requireBodyParam(formData : {[key:string]:any}, name : string) : ReturnBase | undefined {
        if (!(name in formData)) return {
            ok: false,
            error: "invalid_request",
            error_description: name + " is required"
        };
        return undefined;
    }

    getAuthorizeQuery(url: URL) : {query?: AuthorizeQueryType, error: ReturnBase} {
        let error = this.requireGetParam(url, "response_type"); if (error) return {error};
        error = this.requireGetParam(url, "client_id"); if (error) return {error};
        error = this.requireGetParam(url, "redirect_uri"); if (error) return {error};
        error = this.requireGetParam(url, "state"); if (error) return {error};
        const response_type = url.searchParams.get("response_type") ?? "";
        const client_id = url.searchParams.get("client_id") ?? "";
        const redirect_uri = url.searchParams.get("redirect_uri") ?? "";
        const scope = url.searchParams.get("scope") ?? undefined;
        const state = url.searchParams.get("state") ?? "";
        const code_challenge = url.searchParams.get("code_challenge") ?? undefined;
        const code_challenge_method = url.searchParams.get("code_challenge_method") ?? undefined;
        const next = url.searchParams.get("next") ?? undefined;

        let query : AuthorizeQueryType = {
            response_type,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
            next,
        }
        return {query, error: {error: "Unknown error", error_description: "Unknown error", ok: true}};
    }

    private async getMfaChallengeQuery(event : RequestEvent) : Promise<{query?: MfaChallengeBodyType, error: ReturnBase}> {
        let form = new JsonOrFormData();
        await form.loadData(event);
        const formData = form.toObject();
        let error = this.requireBodyParam(formData, "client_id"); if (error) return {error};
        error = this.requireBodyParam(formData, "challenge_type"); if (error) return {error};
        error = this.requireBodyParam(formData, "mfa_token"); if (error) return {error};
        error = this.requireBodyParam(formData, "authenticator_id"); if (error) return {error};
        const client_id = formData.client_id ?? "";
        const challenge_type = formData.challenge_type ?? "";
        const mfa_token = formData.mfa_token ?? "";
        const authenticator_id = formData.authenticator_id ?? "";
        const client_secret = formData.client_secret ?? undefined;

        let query : MfaChallengeBodyType = {
            client_id,
            client_secret,
            challenge_type,
            mfa_token,
            authenticator_id,
        }
        return {query, error: {error: "Unknown error", error_description: "Unknown error", ok: true}};
    }

    private async mfaAuthenticators(event : RequestEvent) :
        Promise<MfaAuthenticatorResponse[]|
            {error? : string, error_description? : string}> {

        const authHeader = event.request.headers.get('authorization')?.split(" ");
        if (!authHeader || authHeader.length != 2) {
            return {
                error: "access_denied",
                error_description: "Invalid authorization header"
            };
        }
        const mfa_token = authHeader[1];
        const resp = 
            await this.authServer.mfaAuthenticatorsEndpoint(mfa_token);
        if (resp.authenticators) {
            return resp.authenticators
        }
        const ce = CrossauthError.fromOAuthError(resp.error??"server_error");
        return {
            error: ce.oauthErrorCode,
            error_description: ce.message,
        };

    }

    private async mfaChallenge(event : RequestEvent) : 
        Promise<MfaChallengeReturn> {

        let qresp = await this.getMfaChallengeQuery(event);
        if (!qresp.query) return qresp.error
        let query : MfaChallengeBodyType = qresp.query;
    
        const resp = 
            await this.authServer.mfaChallengeEndpoint(query.mfa_token,
                query.client_id,
                query.client_secret,
                query.challenge_type,
                query.authenticator_id);
        
        return resp;

    }

    private getClientIdAndSecret(formData : {[key:string]:any}, event : RequestEvent) {
        // OAuth spec says we may take client credentials from 
        // authorization header
        let client_id = formData.client_id;
        let client_secret = formData.client_secret;
        const authorizationHeader = event.request.headers.get("authorization");
        if (authorizationHeader) {
            let client_id1 : string|undefined;
            let client_secret1 : string|undefined;
            const parts = authorizationHeader.split(" ");
            if (parts.length == 2 &&
                parts[0].toLocaleLowerCase() == "basic") {
                const decoded = Crypto.base64Decode(parts[1]);
                const parts2 = decoded.split(":", 2);
                if (parts2.length == 2) {
                    client_id1 = parts2[0];
                    client_secret1 = parts2[1];
                }
            }
            if (client_id1 == undefined || client_secret1 == undefined) {
                CrossauthLogger.logger.warn(j({
                    msg: "Ignoring malform authenization header " + 
                        authorizationHeader}));
            } else {
                client_id = client_id1;
                client_secret = client_secret1;
            }
        }
        return {client_id, client_secret};

    }

    private async applyUserCode(userCode : string, event : RequestEvent, user: User) : Promise<DevicePageData> {
        // if there is a user code, apply it.  Otherwise we will show the form
        // and it will be processed by the action
        try {
            const ret = await this.authServer.deviceEndpoint({userCode, user});
            if (ret.error) {
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: ret.error,
                    error_description: ret.error_description,

                }
            }
            if (!ret.client_id) {
                CrossauthLogger.logger.error(j({msg: "No client id found for user code", userCodeHash: Crypto.hash(userCode), ip: event.request.referrer, username: event.locals.user?.username}));
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: "server_error",
                    error_description: "No client id found for user code",
                }
            }
            if (ret.error == "access_denied") {
                CrossauthLogger.logger.error(j({msg: "Incorrect user code given", userCodeHash: Crypto.hash(userCode), ip: event.request.referrer, username: event.locals.user?.username}));
                if (this.authServer.userCodeThrottle > 0) {
                    let wait = (ms : number) => new Promise(resolve => setTimeout(resolve, ms));
                    await wait(this.authServer.userCodeThrottle);    
                }
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: true,
                    error: ret.error,
                    error_description: ret.error_description,
                }
            } else if (ret.error == "expired_token") {
                CrossauthLogger.logger.error(j({msg: "Expired user code", userCodeHash: Crypto.hash(userCode), ip: event.request.referrer, username: event.locals.user?.username}));
                return {
                    ok: false,
                    completed: false,
                    retryAllowed: false,
                    error: ret.error,
                    error_description: ret.error_description,
                }

            }

            const client = await this.clientStorage.getClientById(ret.client_id);

            // if the user needs to authorize scopes, tell the caller this
            // - user code will have not been set to ok in the above call yet
            if (ret.scopeAuthorizationNeeded) {
                return {
                    ok: true,
                    completed: false,
                    retryAllowed: true,
                    authorizationNeeded: {
                        user,
                        client_id: ret.client_id,
                        client_name: client.client_name,
                        scope: ret.scope,
                        scopes : ret.scope ? ret.scope.split(" ") : [],
                        csrfToken: event.locals.csrfToken
                    },
                    user: event.locals.user,
                    csrfToken: event.locals.csrfToken,
                    user_code: userCode,
                }
            
            } else {
                // all scopes were authorized - this completes the flow
                return {
                    ok: true,
                    completed: true,
                    retryAllowed: false,
                    user: event.locals.user,
                    csrfToken: event.locals.csrfToken,
                }
            }
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            CrossauthLogger.logger.error(j({msg: ce.message, cerr: ce}));
            return {
                ok: false,
                completed: false,
                retryAllowed: true,
                error: ce.oauthErrorCode,
                error_description: ce.message,
            }
        }
    }


    ////////////////////////////////////////////////////////////////
    // Sveltekit user endpoints

    /**
     * Fields that are returned by all endpoint load methods
     * 
     * See class description
     * @param event the SvelteKit event
     * @returns an object with:
     *   - `user` the `User` object from `event.locals.user`
     *   - `csrfToken` the CSRF token from `event.locals.csrfToken`
     */
    baseEndpoint(event : RequestEvent) {
        return {
            user : event.locals.user,
            csrfToken: event.locals.csrfToken,
        }
    }

    /**
     * `get` function for the oidcConfiguration endpoint.
     * 
     * See class description for details.
     */
    readonly oidcConfigurationEndpoint = {
        get: async (_event : RequestEvent) => {
            return json(this.authServer.oidcConfiguration({
                authorizeEndpoint: this.authorizeEndpointUrl, 
                tokenEndpoint: this.tokenEndpointUrl, 
                jwksUri: this.jwksEndpointUrl, 
                additionalClaims: []
                }
            ));
        },
    };

    /**
     * `get` function for the jwks endpoint.
     * 
     * See class description for details.
     */
    readonly jwksGetEndpoint = {

        get: async (_event : RequestEvent) => {
            try {
                return json(this.authServer.jwks());
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                });
            }
        },
    }

    /**
     * `get` function for the csrfToken endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly getCsrfTokenEndpoint = {

        get: async (event : RequestEvent) => {
            if (!this.csrfTokens) return json({
                ok: false,
                error: "invalid_request",
                error_description: "No CSRF token",
            });
            let csrfCookieValue = "";
            try {
                const {csrfCookie,
                    csrfFormOrHeaderValue} = await this.createCsrfToken();
                csrfCookieValue = csrfCookie.value;
                event.cookies.set(csrfCookie.name,
                    csrfCookie.value,
                    toCookieSerializeOptions(csrfCookie.options));
                return json({ok: true, csrfToken: csrfFormOrHeaderValue});
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.error(j({
                    msg: "getcsrftoken failure",
                    user: event.locals.user?.username,
                    hashedCsrfCookie: Crypto.hash(csrfCookieValue.split(".")[0]),
                    error: ce.code,
                    errorCodeName: ce.codeName
                }));
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.error({cerr: e});
                return json({
                    ok: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                });
            }
        },
    }

    async storeSessionData(event: RequestEvent, sessionData: {[key:string]:any}, sessionDataName: string) {

        // we need a session to save the state
        if (this.svelteKitServer.sessionServer) {
            // if we are using Crossauth's session server and there is nop
            // session, we can create an anonymous one.
            // For other session adapters, we assume the session was already
            // creeated or that the session adapter can create one automaticall
            // when updateSessionData is called
            let sessionCookieValue = this.svelteKitServer.sessionServer?.getSessionCookieValue(event);
            if (!sessionCookieValue) {
                sessionCookieValue = 
                    await this.svelteKitServer.sessionServer?.createAnonymousSession(event,
                        { [sessionDataName]: sessionData });
            } else {
                await this.svelteKitServer.sessionAdapter?.updateSessionData(event,
                    sessionDataName,
                    sessionData);
            }
        } else {
            await this.svelteKitServer.sessionAdapter?.updateSessionData(event,
                sessionDataName,
                sessionData);
        }

    }

    private async redirectError(redirect_uri: string|undefined, error: string, error_description: string) {
        if (redirect_uri) {
            throw this.redirect(302, redirect_uri + "?error=" + encodeURIComponent(error) + "&error_description=" + encodeURIComponent(error_description));
        } else {
            throw this.error(500, error_description);
        }
    }
    
    /**
     * Called from the client side of an auth server with an upstream auth server
     * @param event Sveltekit event
     * @param url URL the originating client originally made to our auth server's /authorize endpoint
     * @param upstream the label of the upstream client if we have seeral
     * @returns 
     */
    async saveDownstreamAuthzCodeFlow(event: RequestEvent, url: URL, upstream?: string) {

        let upstreamClient : OAuthClientBackend|undefined = undefined;
        let upstreamClientOptions : UpstreamClientOptions|undefined = undefined;
        let upstreamLabel = upstream;
        if (this.authServer.upstreamClient && this.authServer.upstreamClientOptions) {
            upstreamClient = this.authServer.upstreamClient;
            upstreamClientOptions = this.authServer.upstreamClientOptions
        }
        else if (this.authServer.upstreamClients && this.authServer.upstreamClientOptionss) {
            if (upstreamLabel)  {
                if (upstreamLabel in this.authServer.upstreamClients) {
                    upstreamClient = this.authServer.upstreamClients[upstreamLabel]
                    upstreamClientOptions = this.authServer.upstreamClientOptionss[upstreamLabel]
                } else {
                    CrossauthLogger.logger.error(j({"msg": "No upstream client defined for " + upstreamLabel}))
                    return {
                        ok: false,
                        error: "server_error",
                        error_description: "No upstream client defined for " + upstreamLabel
                    }
                }
            } else {
                // this may be legitimate, if the request is to log in with a local account
                CrossauthLogger.logger.warn(j({"msg": "1 upstreamClients defined but no upstream parameter given in authorize request"}))
            }
        }

        if (upstreamClient && upstreamClientOptions) {

            const state = Crypto.randomValue(32);
            let resp = this.getAuthorizeQuery(url);
            if (!resp.query) return resp.error
            let query : AuthorizeQueryType = resp.query;

            CrossauthLogger.logger.debug(j({"msg": `Have upstream client with redirect_uri ${query.redirect_uri}`}))
            if (query.response_type == "code") {

                // validate client
                let client : OAuthClient;
                try {
                    client = await this.clientStorage.getClientById(query.client_id);
                }
                catch (e) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Unauthorized, "Client is unauthorized");
                }
                let scopes : string[]|undefined = undefined;
                if (query.scope) scopes = decodeURIComponent(query.scope).split(" ");
                scopes = scopes?.filter((a) => (a.length > 0));

                // construct a url to call the /authorize endpoint on the upstream auth server
                const resp = await upstreamClient.startAuthorizationCodeFlow(state, { scope: query.scope, codeChallenge: query.code_challenge, pkce: query.code_challenge!=undefined});
                if (resp.error) {
                    return {
                        ok: false,
                        error: resp.error,
                        error_description: resp.error_description,
                    }
                } else {
                    // create an authorization code
                    const codeResp = await this.authServer.getAuthorizationCode(client, query.redirect_uri, scopes, state, query.code_challenge, query.code_challenge_method);
                    if (!codeResp.code) {
                        return { 
                            ok: false,
                            error: "server_error", 
                            error_description: "Couldn't create authorization code",
                        };
    
                    }

                    // store the original /authorize request in the session
                    const sessionData = {
                        scope: query.scope, 
                        state,
                        code:codeResp.code,
                        orig_client_id: query.client_id,
                        orig_redirect_uri: query.redirect_uri,
                        orig_state: query.state,
                        upstream_label: upstreamLabel,
                        next: query.next,
                    };
                    if (!upstreamClientOptions.options.redirect_uri) {
                        return { 
                            ok: false,
                            error: "server_error", 
                            error_description: "redirect uri not given for upstream client",
                        }
    
                    }
                    const sessionDataName = upstreamClientOptions.sessionDataName ?? DEFAULT_UPSTREAM_SESSION_DATA_NAME;
                    await this.storeSessionData(event, sessionData, sessionDataName);
                    let url = resp.url;
                    CrossauthLogger.logger.debug(j({msg: "upstream url " + url}))
                    //CrossauthLogger.logger.debug(j({msg: "upstream base url " + this.authServer.upstreamAuthServerBaseUrl}))

                    // Redirect to the /authorize endpoint on the upstream server
                    throw this.redirect(302, url);
                }
            } else {
                return { 
                    ok: false,
                    error: "invalid_request", 
                    error_description: "authorize can only be called with response_type code",
                };
            }
        }
   }

    /**
     * `load` and `actions` functions for the authorize endpoint.
     * 
     * See class description for details.  
     */
    readonly authorizeEndpoint = {

        load: async (event : RequestEvent) : Promise<AuthorizePageData> => {
            if (!(this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
            this.authServer.validFlows.includes(OAuthFlows.OidcAuthorizationCode))) {
                throw this.error(401, "authorize cannot be called because the authorization code flows are not supported");
            }

            // handle the case where we have an upstream authz server
            // either throw redirect or return error
            let upstreamClient : OAuthClientBackend|undefined = undefined;
            let upstreamClientOptions : UpstreamClientOptions|undefined = undefined;
            let upstreamLabel : string|undefined = undefined;
            if (this.authServer.upstreamClient && this.authServer.upstreamClientOptions) {
                upstreamClient = this.authServer.upstreamClient;
                upstreamClientOptions = this.authServer.upstreamClientOptions
            }
            else if (this.authServer.upstreamClients && this.authServer.upstreamClientOptionss) {
                upstreamLabel = event.url.searchParams.get("upstream") ?? undefined;
                if (upstreamLabel)  {
                    if (upstreamLabel in this.authServer.upstreamClients) {
                        upstreamClient = this.authServer.upstreamClients[upstreamLabel]
                        upstreamClientOptions = this.authServer.upstreamClientOptionss[upstreamLabel]
                    } else {
                        CrossauthLogger.logger.error(j({"msg": "No upstream client defined for " + upstreamLabel}))
                        return {
                            ok: false,
                            error: "server_error",
                            error_description: "No upstream client defined for " + upstreamLabel
                        }
                    }
                } else {
                    CrossauthLogger.logger.warn(j({"msg": "2 upstreamClients defined but no upstream parameter given in authorize request"}))
                }
            }
            if (upstreamClient && upstreamClientOptions) {

                const state = Crypto.randomValue(32);
                let resp = this.getAuthorizeQuery(event.url);
                if (!resp.query) return resp.error
                let query : AuthorizeQueryType = resp.query;

                CrossauthLogger.logger.debug(j({"msg": `Have upstream client with redirect_uri ${query.redirect_uri}`}))
                if (query.response_type == "code") {

                    // validate client
                    let client : OAuthClient;
                    try {
                        client = await this.clientStorage.getClientById(query.client_id);
                    }
                    catch (e) {
                        CrossauthLogger.logger.debug(j({err: e}));
                        return {ok: false, error: "unauthorized_client", 
                                error_description: "Client is not authorized"};
                    }
                    let scopes : string[]|undefined = undefined;
                    if (query.scope) scopes = decodeURIComponent(query.scope).split(" ");
                    scopes = scopes?.filter((a) => (a.length > 0));

                    // construct a url to call the /authorize endpoint on the upstream auth server
                    const resp = await upstreamClient.startAuthorizationCodeFlow(state, { scope: query.scope, codeChallenge: query.code_challenge, pkce: query.code_challenge!=undefined});
                    if (resp.error) {
                        return {
                            ok: false,
                            error: resp.error,
                            error_description: resp.error_description,
                        }
                    } else {
                        // create an authorization code
                        const codeResp = await this.authServer.getAuthorizationCode(client, query.redirect_uri, scopes, state, query.code_challenge, query.code_challenge_method);
                        if (!codeResp.code) {
                            return { 
                                ok: false,
                                error: "server_error", 
                                error_description: "Couldn't create authorization code",
                            };
        
                        }

                        // store the original /authorize request in the session
                        const sessionData = {
                            scope: query.scope, 
                            state,
                            code:codeResp.code,
                            orig_client_id: query.client_id,
                            orig_redirect_uri: query.redirect_uri,
                            orig_state: query.state,
                            upstream_label: upstreamLabel,
                            next: query.next,
                        };
                        if (!upstreamClientOptions.options.redirect_uri) {
                            return { 
                                ok: false,
                                error: "server_error", 
                                error_description: "redirect uri not given for upstream client",
                            };
        
                        }
                        // we need a session to save the state
                        const sessionDataName = upstreamClientOptions.sessionDataName ?? DEFAULT_UPSTREAM_SESSION_DATA_NAME;
                        await this.storeSessionData(event, sessionData, sessionDataName);
                        let url = resp.url;
                        CrossauthLogger.logger.debug(j({msg: "upstream url " + url}))
                        //CrossauthLogger.logger.debug(j({msg: "upstream base url " + this.authServer.upstreamAuthServerBaseUrl}))
                        
                        throw this.redirect(302, url);
                    }
                } else {
                    return { 
                        ok: false,
                        error: "invalid_request", 
                        error_description: "authorize can only be called with response_type code",
                    };
                }
            }

            // we don't have an upstream server

            if (!event.locals.user) return this.redirect(302, 
                this.loginUrl+"?next="+encodeURIComponent(event.request.url));

            let resp = this.getAuthorizeQuery(event.url);
            if (!resp.query) return resp.error
            let query : AuthorizeQueryType = resp.query;

            // this just checks they are valid strings and not empty if required, 
            // to avoid XSR vulnerabilities
            CrossauthLogger.logger.debug(j({msg: "validating authorize parameters"}))
            let {error_description} = 
                this.authServer.validateAuthorizeParameters(query);
            let ce : CrossauthError|undefined = undefined;
            if (error_description) {
                ce = new CrossauthError(ErrorCode.BadRequest, error_description);
                CrossauthLogger.logger.error(j({
                    msg: "authorize parameter invalid",
                    cerr: ce,
                    user: event.locals.user?.username
                }));
            }  else {
                CrossauthLogger.logger.error(j({
                    msg: "authorize parameter invalid",
                    user: event.locals.user?.username
                }));

            }

            if (ce) {
                return { 
                    ok: false,
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                };

                //throw this.error(ce.httpStatus, ce.message);
            }

            let hasAllScopes = false;
            CrossauthLogger.logger.debug(j({
                msg: `Checking scopes have been authorized`,
                scope: query.scope }))
            if (query.scope) {
                hasAllScopes = await this.authServer.hasAllScopes(query.client_id,
                    event.locals.user,
                    query.scope.split(" "));

            } else {
                hasAllScopes = await this.authServer.hasAllScopes(query.client_id,
                    event.locals.user,
                    [null]);

            }
            if (hasAllScopes) {
                CrossauthLogger.logger.debug(j({
                    msg: `All scopes authorized`,
                    scope: query.scope
                }))
                // all scopes have been previously authorized 
                // - create an authorization code
                const resp = await this.authorize(event, true, {
                    responseType: query.response_type,
                    client_id : query.client_id,
                    redirect_uri: query.redirect_uri,
                    scope: query.scope,
                    state: query.state,
                    codeChallenge: query.code_challenge,
                    codeChallengeMethod: query.code_challenge_method,
                });
                // the above either throws a redirect or returns with an error
                return {
                    ok: false,
                    error: resp.error ?? "server_error",
                    error_description: resp.error_description ?? "An unexpected error occurred",
                }
            
            } else {
                // requesting new scopes - signal caller to show authorization
                // page to user
                CrossauthLogger.logger.debug(j({
                    msg: `Not all scopes authorized`,
                    scope: query.scope
                }))
                try {
                    const client = 
                        await this.clientStorage.getClientById(query.client_id);
                    
                    return {
                        ok: true,
                        authorizationNeeded: {
                            user: event.locals.user,
                            response_type: query.response_type,
                            client_id : query.client_id,
                            client_name : client.client_name,
                            redirect_uri: query.redirect_uri,
                            scope: query.scope,
                            scopes: query.scope ? query.scope.split(" ") : undefined,
                            state: query.state,
                            code_challenge: query.code_challenge,
                            code_challenge_method: query.code_challenge_method,
                            csrfToken: event.locals.csrfToken,
    
                        },
                        ...this.baseEndpoint,
                    };
                } catch (e) {
                    const ce = e as CrossauthError;
                    CrossauthLogger.logger.debug(j({err: ce}));
                    return {
                        ok: false,
                        error: "unauthorized_client",
                        error_description: "Not a valid client",
                    };
                }
            }
        }, // load

        actions: {
            default: async ( event : RequestEvent ) : Promise<AuthorizeActionData> => {
                let formData : {[key:string]:string}|undefined = undefined;
                try {
                    // get form data
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
                    const authorized = data.getAsBoolean('authorized');
                    const response_type = formData.response_type;
                    const client_id = formData.client_id;
                    const redirect_uri = formData.redirect_uri;
                    const scope = formData.scope;
                    const state = formData.state;
                    const code_challenge = formData.code_challenge;
                    const code_challenge_method = formData.code_challenge_method;
                    let missing = undefined;
                    if (authorized == undefined) missing = "authorized";
                    if (!response_type) missing = "response_type";
                    else if (!client_id) missing = "client_id";
                    else if (!redirect_uri) missing = "redirect_uri";
                    else if (!state) missing = "state";
                    if (missing) {
                        return {
                            ok: false,
                            error: "invalid_request",
                            error_description: "Invalid form: does not contain " + missing + " parameter"
                        };
                    }
                    
                    // this should not be called if a user is not logged in
                    if (!event.locals.user) return this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                    if (this.svelteKitServer.sessionServer?.enableCsrfProtection && !event.locals.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);
   
                    // The following will either return an error or will throw a redirect
                    const resp = await this.authorize(event, authorized ?? false, {
                        responseType: response_type,
                        client_id : client_id,
                        redirect_uri: redirect_uri,
                        scope: scope,
                        state: state,
                        codeChallenge: code_challenge,
                        codeChallengeMethod: code_challenge_method,
                    });
                    // the above either throws a redirect or returns with an error
                    return {
                        ok: false,
                        error: resp.error ?? "server_error",
                        error_description: resp.error_description ?? "An unexpected error occurred",
                    }

                } catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    let ce = CrossauthError.asCrossauthError(e, "Couldn't process authorization code");
                    return {
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                        ok: false,
                        formData,
                    }
                }
            }
        }
    }

    /**
     * `post` function for the token endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly tokenEndpoint = {

        post: async (event : RequestEvent) => {
            let formData : {[key:string]:string}|undefined = undefined;
            try {
                
                if (!(this.authServer.validFlows.includes(OAuthFlows.AuthorizationCode) || 
                    this.authServer.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
                    this.authServer.validFlows.includes(OAuthFlows.OidcAuthorizationCode) ||
                    this.authServer.validFlows.includes(OAuthFlows.ClientCredentials) ||
                    this.authServer.validFlows.includes(OAuthFlows.RefreshToken) ||
                    this.authServer.validFlows.includes(OAuthFlows.Password) ||
                    this.authServer.validFlows.includes(OAuthFlows.PasswordMfa ||
                    this.authServer.validFlows.includes(OAuthFlows.DeviceCode)))) {
                    return json({
                        ok: false,
                        error: "invalid_request",
                        error_description: "Token endpoint cannot be called as the supported OAuth flow types don't require it",
                    }, {status: 500});
                }
    
                // get form data
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                const {client_id, client_secret} = this.getClientIdAndSecret(formData, event);

                // if the grant type is authorization_code and we have an upstream client
                // defined, we should already have tokens stored with the authoriazion code
                let upstreamClient : OAuthClientBackend|undefined = undefined;
                let upstreamClientOptions : UpstreamClientOptions|undefined = undefined;
                let upstreamLabel : string|undefined = undefined;
                if (formData.grant_type == "authorization_code") {
                    if (this.authServer.upstreamClient && this.authServer.upstreamClientOptions) {
                        upstreamClient = this.authServer.upstreamClient;
                        upstreamClientOptions = this.authServer.upstreamClientOptions
                    } else {
                        const codeData = await this.authServer.getAuthorizationCodeData(formData.code);
                        if (codeData?.upstream && this.authServer.upstreamClients && this.authServer.upstreamClientOptionss) {
                            upstreamClient = this.authServer.upstreamClients[codeData?.upstream];
                            upstreamClientOptions = this.authServer.upstreamClientOptionss[codeData?.upstream]
                            upstreamLabel = codeData.upstream
                        }
                    }

                }
                

                if (formData.grant_type == "authorization_code" && 
                    upstreamClient && upstreamClientOptions) {

                        // if it is the authorization code flow and we have an upstream client,
                        // get the tokens that the our upstream redirect uri saved, keyed on 
                        // the authorization code
                        const codeData = await this.authServer.getAuthorizationCodeData(formData.code);
                        if (codeData == undefined) {
                            return json({
                                error: "access_denied",
                                error_description: "Invalid or expired authorization code",
                            })
                        }
                        if (!codeData.access_token) {
                            return json({error: "access_denied", error_description: "No access token was issued"}, {status: 401});
                        } 

                        await this.authServer.deleteAuthorizationCodeData(formData.code);

                        // determine whether we are also creating a refresh token
                        let createRefreshToken = false;
                        if (this.authServer.issueRefreshToken) {
                            createRefreshToken = true;
                        }
                        if (this.authServer.issueRefreshToken && 
                            this.authServer.rollingRefreshToken) {
                            createRefreshToken = true;
                        }

                        // get client
                        const clientResponse = await this.authServer.getClientById(client_id);
                        if (!clientResponse.client) return json({
                            error: clientResponse.error,
                            error_description: clientResponse.error_description}, {status: CrossauthError.fromOAuthError(clientResponse.error??"server_error").httpStatus}); 
                        const client = clientResponse.client;

                        let refreshToken = await this.authServer.createRefreshToken(client, {upstreamRefreshToken: codeData.refresh_token, upstreamLabel: upstreamLabel})

                        // save tokens so that this is treated as the logged in user
                        // doesn't work - no cookie
                        /*await this.storeSessionData(event, {
                            access_token: codeData.access_token,
                            id_token: codeData.id_token,
                            id_payload: codeData.id_payload,
                            refresh_token: refreshToken ?? upstreamLabel + ":" + codeData.refresh_token,
                            expires_in: codeData.expires_in,
                            upstream: upstreamLabel

                        }, this.sessionDataName)*/

                        return json({
                            access_token: codeData.access_token,
                            id_token: codeData.id_token,
                            id_payload: codeData.id_payload,
                            refresh_token: refreshToken ?? upstreamLabel + ":" + codeData.refresh_token,
                            expires_in: codeData.expires_in,
                            upstream: upstreamLabel,
                        });
                }

                // if refreshTokenType is not "json", check if there
                // is a refresh token in the cookie.
                // there must also be a valid CSRF token
                let refreshToken = formData.refresh_token;
                let refreshTokenCookie = event.cookies.get(this.refreshTokenCookieName);
                if (((this.refreshTokenType == "cookie" && refreshTokenCookie) ||
                    (this.refreshTokenType == "both" && refreshTokenCookie && 
                    refreshToken == undefined)) &&
                    this.csrfTokens /* this part is just for typescript checker */) {  
                    const csrfCookie = event.cookies.get(this.csrfTokens.cookieName);
                    let csrfHeader = event.request.headers.get(this.csrfTokens.headerName.toLowerCase());
                    if (Array.isArray(csrfHeader)) csrfHeader = csrfHeader[0];
                    if (!csrfCookie || !csrfHeader) {
                        return json({
                            ok: false,
                            error: "access_denied",
                            error_description: "Invalid csrf token",
                        }, {status: 401});
                    }
                    try {
                        this.csrfTokens.validateDoubleSubmitCsrfToken(csrfCookie, csrfHeader)
                    } catch (e) {
                        CrossauthLogger.logger.debug(j({err: e}));
                        CrossauthLogger.logger.warn(j({cerr: e, msg: "Invalid csrf token", client_id: formData.client_id}));
                        return json({
                            ok: false,
                            error: "access_denied",
                            error_description: "Invalid csrf token",
                        }, {status: 401});
                    }
                    refreshToken = refreshTokenCookie;
                }
        
                const resp = await this.authServer.tokenEndpoint({
                    grantType: formData.grant_type,
                    client_id : client_id,
                    client_secret : client_secret,
                    scope: formData.scope,
                    codeVerifier: formData.code_verifier,
                    code: formData.code,
                    username: formData.username,
                    password: formData.password,
                    mfaToken: formData.mfa_token,
                    oobCode: formData.oob_code,
                    bindingCode: formData.binding_code,
                    otp: formData.otp,
                    refreshToken: refreshToken,
                    deviceCode: formData.device_code,
                });


                if (resp.refresh_token && this.refreshTokenType != "json") {
                    this.setRefreshTokenCookie(event, resp.refresh_token, resp.expires_in);
                }
                if (resp.error == "authorization_pending") {
                    return json(resp);
                }
                if (resp.error || !resp.access_token) {
                    let error = "server_error";
                    let errorDescription = "Neither code nor error received when requestoing authorization";
                    if (resp.error) error = resp.error;
                    if (resp.error_description) errorDescription = resp.error_description;
                    const ce = CrossauthError.fromOAuthError(error, errorDescription);
                    CrossauthLogger.logger.error(j({cerr: ce}));
                    return json(resp, {status: ce.httpStatus});
                }
                return json(resp);
            
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                }, {status: ce.httpStatus});
            }
        },
    }

    // The upstream auth server will redirect to hear with an authorization code
    readonly upstreamRedirectUriEndpoint = {

        get: async (event : RequestEvent, upstream?: string) => {
            let oauthData : {[key:string]:any} = {};
            try {
                if (!this.authServer.upstreamClientOptions && !this.authServer.upstreamClientOptionss) {
                    CrossauthLogger.logger.error(j({msg: "Cannot call upstreamRedirectUriEndpoint if upstreamClient not defined"}))
                    return json({
                        ok: false,
                        error: "server_error",
                        error_description: "Cannot call upstreamRedirectUriEndpoint if upstreamClient not defined"
                    });
                }
                CrossauthLogger.logger.debug(j({msg: "upstreamRedirectUriEndpoint", upstream}))

                // find which upstream client was used
                let upstreamClient : OAuthClientBackend|undefined = undefined;
                let upstreamClientOptions : UpstreamClientOptions|undefined = undefined;
                if (this.authServer.upstreamClient && this.authServer.upstreamClientOptions) {
                    upstreamClient = this.authServer.upstreamClient
                    upstreamClientOptions = this.authServer.upstreamClientOptions
                } else if (this.authServer.upstreamClients && this.authServer.upstreamClientOptionss) {
                    if (!upstream) {
                        CrossauthLogger.logger.error(j({msg: "Have multiple upstream clients but upstream redirect uri not passed the upstream identifier"}));
                        return this.redirectError(oauthData.orig_redirect_uri, "server_error",  "Have multiple upstream clients but upstream redirect uri not passed the upstream identifier")
                    }
                    upstreamClient = this.authServer.upstreamClients[upstream]
                    upstreamClientOptions = this.authServer.upstreamClientOptionss[upstream]
                }
                if (!upstreamClient || !upstreamClientOptions) {
                    CrossauthLogger.logger.error(j({msg: "upstreamRedirectUri endpoint called but no upstreamClient or merge function set"}));
                    return this.redirectError(oauthData.orig_redirect_uri, "server_error",  "upstreamRedirectUri endpoint called but no upstreamClient or merge function set")
                } 

                // URL contains redirect URI parameters between us and the upstream auth server
                // Session data contains parameters the originating client sent to our /authorize endpoint 
                const code = event.url.searchParams.get("code") ?? "";
                const state = event.url.searchParams.get("state") ?? undefined;
                const error = event.url.searchParams.get("error") ?? undefined;
                const error_description = event.url.searchParams.get("error") ?? undefined;
                const sessionDataName = upstreamClientOptions.sessionDataName ?? DEFAULT_UPSTREAM_SESSION_DATA_NAME;
                oauthData = await this.svelteKitServer.sessionAdapter?.getSessionData(event, sessionDataName) ?? {};
                if (this.authServer.upstreamClients && (!("upstream_label" in oauthData ) || !(oauthData.upstream_label in this.authServer.upstreamClients))) {
                    return this.redirectError(oauthData.orig_redirect_uri, "server_error", "Invalid upstream client found in saessom")
                }
                if (this.authServer.upstreamClients) {
                    upstreamClient = this.authServer.upstreamClients[oauthData.upstream_label]
                }
                if (oauthData?.state != state) {
                    CrossauthLogger.logger.error(j({msg: "State does not match"}))
                    throw new CrossauthError(ErrorCode.Unauthorized, "State does not match");
                }

                // make the post to the upstream server's token endpoint to receive the tokens
                const resp =  await upstreamClient.redirectEndpoint({
                    code, 
                    scope: oauthData?.scope, 
                    codeVerifier: oauthData?.codeVerifier,
                    error,
                    errorDescription: error_description});
                    if (resp.error) {
                    CrossauthLogger.logger.error(j({msg: resp.error_description}));
                    return this.redirectError(oauthData.orig_redirect_uri, resp.error, resp.error_description ?? "unknown error")
                }

                // some servers have the access token as a JWT.  For others, it is a simple string.
                // ID token, if present, is always a JWT
                let access_token : string|{[key:string]:any}|undefined = resp.access_token;
                if (resp.access_token && upstreamClientOptions.accessTokenIsJwt) {
                    const resp1 = await upstreamClient.getAccessPayload(resp.access_token, false);
                    if (resp1.error) return json(resp1);
                    else if (resp1.payload) access_token =resp1.payload;
                    else {
                        CrossauthLogger.logger.error(j({msg: "No error or access payload received when querying access token"}));
                        return this.redirectError(oauthData.orig_redirect_uri, "server_error", "No error or access payload received when querying access token")
                    }   
                }

                // call user-supplied merge function to combine received ID token with entry in user storage
                const mergeResponse = await upstreamClientOptions.tokenMergeFn(access_token??"", resp.id_payload, this.authServer.userStorage);

                if (mergeResponse.authorized) {

                        // make ID token from the merged payload.  If the access token is a JWT, do the same for it
                        const ret = await this.authServer.createTokensFromPayload(oauthData.orig_client_id,
                            typeof(mergeResponse.access_payload) == "string" ? undefined : mergeResponse.access_payload, mergeResponse.id_payload
                        );

                        // I think this is redundant...
                        oauthData = {
                            ...oauthData,
                            access_token: ret.access_token,
                            id_token: ret.id_token,
                            id_payload: ret.id_payload,
                            expires_in: ret.expires_in,
                            refresh_token: resp.refresh_token,
                        };

                        // get the tokens saved for the originating client when it's redirect URI called our token endpoint
                        let authzData = await this.authServer.getAuthorizationCodeData(oauthData.code);
                        authzData = {
                            ...authzData,
                            access_token: ret.access_token,
                            id_token: ret.id_token,
                            id_payload: ret.id_token,
                            refresh_token: resp.refresh_token,
                            expires_in: ret.expires_in,
                            upstream
                        }

                        // save our new tokens, keyed on the authorization code
                        await this.authServer.setAuthorizationCodeData(oauthData.code, authzData);

                        // redirect to the originating client's redirect URI 
                        // our token endpoint will return the saved tokens
                        throw this.redirect(302, this.authServer.redirect_uri(
                            oauthData.orig_redirect_uri,
                            oauthData.code,
                            oauthData.orig_state
                        ));                        
                } else {
                    CrossauthLogger.logger.error(j({msg: mergeResponse.error_description ?? "Error merging tokens"}));
                    return this.redirectError(oauthData.orig_redirect_uri, mergeResponse.error ?? "server_error", mergeResponse.error_description ?? "Error merging tokens")
                }

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.redirectError(oauthData.orig_redirect_uri, ce.oauthErrorCode, ce.message)
            }
        },
    };

    /**
     * `get` and `post` functions for the mfa/authenticators endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly mfaAuthenticatorsEndpoint = {

        get: async (event : RequestEvent) => {
            try {
                // get form data
                var data = new JsonOrFormData();
                await data.loadData(event);
                return json(await this.mfaAuthenticators(event));

            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                });

            }
        },

        post: async (event : RequestEvent) => {
            try {
                // get form data
                var data = new JsonOrFormData();
                await data.loadData(event);
                let resp = await this.mfaAuthenticators(event);
                let status = 200;
                if (!Array.isArray(resp) && resp.error == "access_denied") status = 401;
                else if (!Array.isArray(resp) && resp.error) status = 500;
                return json(resp, {status});

            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                }, {status: ce.httpStatus});

            }
        },
    };

    /**
     * `post` function for the mfa/challenge endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly mfaChallengeEndpoint = {

        post: async (event : RequestEvent) => {
            try {
                // get form data
                var data = new JsonOrFormData();
                await data.loadData(event);
                const resp = await this.mfaChallenge(event);
                let status = 200;
                if (resp.error == "access_denied") status = 401;
                else if (resp.error) status = 500;
                return json(resp, {status});

            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                }, {status: 500});

            }
        },
    };

    /**
     * `post` function for the device_authorization endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly deviceAuthorizationEndpoint = {

        post: async (event : RequestEvent) => {
            let formData : {[key:string]:string}|undefined = undefined;
            try {
                
                if (!(this.authServer.validFlows.includes(OAuthFlows.DeviceCode))) {
                    return json({
                        ok: false,
                        error: "invalid_request",
                        error_description: "Device authorization endpoint cannot be called as the supported OAuth flow types don't require it",
                    });
                }
    
                // get form data
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                const {client_id, client_secret} = this.getClientIdAndSecret(formData, event);

        
                const resp = await this.authServer.deviceAuthorizationEndpoint({
                    client_id : client_id,
                    client_secret : client_secret,
                    scope: formData.scope,
                });

                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, resp.error_description);
                    CrossauthLogger.logger.error(j({cerr: ce}));
                    return json(resp, {status: 500});
                }
                if (!resp.device_code || !resp.user_code || !resp.verification_uri || !resp.verification_uri_complete || !resp.expires_in) {
                    let error = "server_error";
                    let errorDescription ="Device authorization result has missing data";
                    const ce = new CrossauthError(ErrorCode.UnknownError, errorDescription);
                    CrossauthLogger.logger.error(j({cerr: ce}));
                    return json({
                        error,
                        error_description: errorDescription,
                    }, {status: 500});
                }
                
                return json(resp);
            
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                return json({ 
                    error: ce.oauthErrorCode, 
                    error_description: ce.message
                }, {status: 500});
            }
        },
    }

    /**
     * `load` and `actions` functions for the authorize endpoint.
     * 
     * See class description for details.  Not needed if you disable CSRF
     * protection to rely on Sveltekit's.
     */
    readonly deviceEndpoint = {

        load: async (event : RequestEvent) : Promise<DevicePageData> => {
            if (!(this.authServer.validFlows.includes(OAuthFlows.DeviceCode))) {
                throw this.error(401, "device cannot be called because the device code flow is not supported");
            }
            if (!event.locals.user) return this.redirect(302, 
                this.loginUrl+"?next="+encodeURIComponent(event.request.url));

            let userCode = event.url.searchParams.get("user_code");
                // if there is a user code, apply it.  Otherwise we will show the form
                // and it will be processed by the action
                if (userCode) {
                    return await this.applyUserCode(userCode, event, event.locals.user);
                } else {
                    // no user code given - prompt user for it
                    return {
                        ok: true,
                        completed: false,
                        retryAllowed: true,
                        user: event.locals.user,
                        csrfToken: event.locals.csrfToken,
                    }

                }
        }, // load

        actions: {
            userCode: async ( event : RequestEvent ) : Promise<DevicePageData> => {
                if (!event.locals.user) throw this.error(401, "Access Denied");

                try {
                    // get form data
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    const userCode = data.get('user_code');
                    if (!userCode) {
                        return {
                            ok: false,
                            completed: false,
                            retryAllowed: true,
                            error: "access_denied",
                            error_description: "No user code given",
                        }
                    }

                    return await this.applyUserCode(userCode, event, event.locals.user);
                    
                } catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    let ce = CrossauthError.asCrossauthError(e, "Couldn't validate user code");
                    return {
                        ok: false,
                        completed: false,
                        retryAllowed: true,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }
            },
            authorize: async ( event : RequestEvent ) : Promise<DevicePageData> => {
                let formData : {[key:string]:string}|undefined = undefined;
                try {
                    // get form data
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
                    const authorized = data.getAsBoolean('authorized');
                    const scope = formData.scope;
                    const client_id = formData.client_id;
                    const userCode = formData.user_code;
                    let missing = undefined;
                    if (authorized == undefined) missing = "authorized";
                    if (client_id == undefined) missing = "client_id";
                    if (userCode == undefined) missing = "user_code";
                    if (missing) {
                        return {
                            ok: false,
                            completed: false,
                            retryAllowed: false,
                            error: "invalid_request",
                            error_description: "Invalid form: does not contain " + missing + " parameter"
                        };
                    }
                    
                    // this should not be called if a user is not logged in
                    if (!event.locals.user) return this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                    if (this.svelteKitServer.sessionServer?.enableCsrfProtection && !event.locals.csrfToken) throw new CrossauthError(ErrorCode.InvalidCsrf);
   
                    const ret = await this.authServer.validateAndPersistScope(client_id, scope, event.locals.user);
                    if (ret.error) {
                        return {
                            ok: false,
                            completed: false,
                            retryAllowed: false,
                            error: "unauthorized_client",
                            error_description: "You did not authorize access to your account"
                        };
                    }
                    return await this.applyUserCode(userCode, event, event.locals.user);

                } catch (e) {
                    if (SvelteKitServer.isSvelteKitError(e) || SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    let ce = CrossauthError.asCrossauthError(e, "Couldn't process authorization code");
                    return {
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                        ok: false,
                        completed: false,
                        retryAllowed: false,
                    }
                }
            }

        }
    }

};

