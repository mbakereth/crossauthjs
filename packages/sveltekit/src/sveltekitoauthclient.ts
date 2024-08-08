import { jwtDecode } from "jwt-decode";
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    OAuthFlows,
    type OAuthTokenResponse,
    j, 
    type MfaAuthenticatorResponse} from '@crossauth/common';
import {
    setParameter,
    ParamType,
    Crypto,
    OAuthClientBackend } from '@crossauth/backend';
import type { OAuthClientOptions } from '@crossauth/backend';
import { SvelteKitServer } from './sveltekitserver';
import { json } from '@sveltejs/kit';
import type { RequestEvent } from '@sveltejs/kit';
import { JsonOrFormData } from './utils';

export type SvelteKitErrorFn = (server: SvelteKitServer,
    event: RequestEvent,
    ce: CrossauthError) => Promise<Response>;

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link FastifyOAuthClient}.
 */
export interface SvelteKitOAuthClientOptions extends OAuthClientOptions {

    /** 
     * You will have to create a route for the redirect Uri, using
     * the `redirectUriEndpoint` load function.  But the URL for it
     * here.  It should be an absolute URL.
     * 
     * It should be a fully qualified URL as it is called from
     * the browser in a redriect.
     * 
     * The default is "oauth/authzcode".
     */
    redirectUri ?: string,

    /**
     * When using the BFF (backend-for-frontend) pattern, tokens are saved
     * in the `data` field of the session ID.  They are saved in the JSON
     * object with this field name.  Default `oauth`.
     */
    sessionDataName? : string,

    /**
     * If the {@link FastifyOAuthClientOptions.tokenResponseType} is
     * `saveInSessionAndRedirect`, this is the relative URL that the usder
     * will be redirected to after authorization is complete.
     */
    authorizedUrl? : string,

    /**
     * Relative URL to redirect user to if login is required.
     */
    loginUrl? : string,

    /**
     * All flows listed here will require the user to login (here at the client).
     * If if a flow is not listed here, there does not need to be a user
     * logged in here at the client.
     * See {@link @crossauth/common!OAuthFlows}.
     */
    loginProtectedFlows? : string[],

    /**
     * This function is called after successful authorization to pass the
     * new tokens to.
     * @param oauthResponse the response from the OAuth `token` endpoint.
     * @param client the fastify OAuth client
     * @param request the Fastify request
     * @param reply the Fastify reply
     * @returns the Fastify reply
     */
    receiveTokenFn?: (oauthResponse: OAuthTokenResponse,
        client: SvelteKitOAuthClient,
        event: RequestEvent) => Promise<Response|TokenReturn|undefined>;

    /**
     * The function to call when there is an OAuth error and
     * {@link SvelteKitOAuthClientOptions.errorResponseType}
     * is `custom`.
     * See {@link SvelteKitErrorFn}.
     */
    errorFn? :SvelteKitErrorFn;

    /**
     * What to do when receiving tokens.
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenResponseType? : 
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "sendInPage" | 
        "custom";

    /**
     * What do do on receiving an OAuth error.
     * See lass documentation for full description.
     */
    errorResponseType? : 
        "sendJson" | 
        "svelteKitError" | 
        "custom",

    /** 
     * Array of resource server endppints to serve through the
     * BFF (backend-for-frontend) mechanism.
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffEndpoints?: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH")[],
        matchSubUrls?: boolean
    }[],

    /**
     * Prefix for BFF endpoints.  Default "bff".
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffEndpointName? : string,

    /**
     * Base URL for resource server endpoints called through the BFF
     * mechanism.
     * See {@link SvelteKitOAuthClient} class documentation for full description.
     */
    bffBaseUrl? : string,

    /**
     * Endpoints to provide to acces tokens through the BFF mechanism,
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenEndpoints? : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[],

    /** Pass the Sveltekit redirect function */
    redirect? : any,

    /** Pass the Sveltekit error function */
    error? : any,
}

////////////////////////////////////////////////////////////////////////////
// Interfaces

export interface AuthorizationCodeFlowReturn {
    success: boolean,
    error? : string,
    error_description? : string
}


export interface TokenReturn extends OAuthTokenResponse {
    id_payload?: {[key:string]:any},
}

export interface RedirectUriReturn extends OAuthTokenResponse {
    success: boolean,
}

////////////////////////////////////////////////////////////////////////////
// DEFAULT FUNCTIONS

async function jsonError(_server: SvelteKitServer,
    _event: RequestEvent,
    ce: CrossauthError) : Promise<Response> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return json({
            success: false,
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCode: ce.code,
            errorCodeName: ce.codeName
    });
}

async function svelteKitError(server: SvelteKitServer,
    _event: RequestEvent,
    ce: CrossauthError) : Promise<Response> {
        throw server.oAuthClient?.error(ce.httpStatus, ce.message);
} 

function decodePayload(token : string|undefined) : {[key:string]: any}|undefined {
    let payload : {[key:string]: any}|undefined = undefined;
    if (token) {
        try {
            payload = JSON.parse(Crypto.base64Decode(token.split(".")[1]))
        } catch (e) {
            CrossauthLogger.logger.error(j({msg: "Couldn't decode id token"}));
        }
    }
    return payload;

}

async function sendJson(oauthResponse: OAuthTokenResponse,
    _client: SvelteKitOAuthClient,
    _event: RequestEvent) : Promise<Response|undefined> {
        return json({success: true, ...oauthResponse, 
            id_payload: decodePayload(oauthResponse.id_token)})
}

function logTokens(oauthResponse: OAuthTokenResponse) {
    if (oauthResponse.access_token) {
        try {
            if (oauthResponse.access_token) {
                const jti = jwtDecode(oauthResponse.access_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got access token", 
                    accessTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.id_token) {
        try {
            if (oauthResponse.id_token) {
                const jti = jwtDecode(oauthResponse.id_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got id token", 
                    idTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.refresh_token) {
        try {
            if (oauthResponse.refresh_token) {
                const jti = jwtDecode(oauthResponse.refresh_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got refresh token", 
                    refreshTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
}

async function updateSessionData(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    ) {
        let sessionCookieValue = client.server.sessionServer?.getSessionCookieValue(event);
        let expires_in = oauthResponse.expires_in;
        if (!expires_in && oauthResponse.access_token) {
            const payload = jwtDecode(oauthResponse.access_token);
            if (payload.exp) expires_in = payload.exp;
        }
        if (!expires_in) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "OAuth server did not return an expiry for the access token");
        }
        const expires_at = Date.now() + (expires_in)*1000;
        if (!sessionCookieValue) {
            sessionCookieValue = 
                await client.server.sessionServer?.createAnonymousSession(event,
                    { [client.sessionDataName]: {...oauthResponse, expires_at} });
        } else {
            const existingData = 
                await client.server.sessionServer?.getSessionData(event, client.sessionDataName);
            await client.server.sessionServer?.updateSessionData(event,
                client.sessionDataName,
                { ...existingData??{},  ...oauthResponse, expires_at });
        }

}

async function saveInSessionAndRedirect(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    ) : Promise<Response|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return client.errorFn(client.server, event, ce);
    }

    logTokens(oauthResponse);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, event);
        }

        return client.redirect(302, client.authorizedUrl);
    } catch (e) {
        const ce = e as CrossauthError;
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        client.errorFn(client.server, event, ce);
    }
}

async function saveInSessionAndLoad(oauthResponse: OAuthTokenResponse,
    client: SvelteKitOAuthClient,
    event: RequestEvent,
    ) : Promise<TokenReturn|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return {
            error: oauthResponse.error,
            error_description: oauthResponse.error_description
        }
    }

    logTokens(oauthResponse);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, event);
        }

    return {
        ...oauthResponse,
        id_payload: decodePayload(oauthResponse.id_token)}
    } catch (e) {
        const ce = e as CrossauthError;
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return {
            error: ce.oauthErrorCode,
            error_description: ce.message,
        }
    }
}

async function sendInPage(oauthResponse: OAuthTokenResponse,
    _client: SvelteKitOAuthClient,
    _event: RequestEvent,
    ) : Promise<TokenReturn|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        return {
            error: oauthResponse.error,
            error_description: oauthResponse.error_description
        }
    }

    logTokens(oauthResponse);

    try {

        return {
            ...oauthResponse,
            id_payload: decodePayload(oauthResponse.id_token)}
        } catch (e) {
        const ce = e as CrossauthError;
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        return {
            error: ce.oauthErrorCode,
            error_description: ce.message,
        }
    }
}


///////////////////////////////////////////////////////////////////////////////
// CLASSES

/**
 * The SvelteKit version of the OAuth client.
 * 
 * Makes requests to an authorization server, using a cofigurable set
 * of flows, which sends back errors or tokens,
 * 
 * When constructing this class, you define what happens with tokens that
 * are returned, or errors that are returned.  You do this with the
 * configuration options {@link SvelteKitOAuthClientOptions.tokenResponseType}
 * and {@link SvelteKitOAuthClientOptions.errorResponseType}.
 * 
 * **{@link SvelteKitOAuthClientOptions.tokenResponseType}**
 * 
 *   - `sendJson` the token response is sent as-is as a JSON Response.  
 *      In addition to the `token` endpoint response fields,
 *      `success: true` and `id_payload` with the decoded 
 *      payload of the ID token are retruned.
 *   - `saveInSessionAndLoad` the response fields are saved in the `data`
 *      field of the session ID in key storage.  In addition, `expires_at` is 
 *      set to the number of seconds since Epoch that the access token expires
 *      at.  When using this method, you should define a SvelteKit page
 *      in your routes and put the the `load` (GET methods) or `actions` 
 *      (POST methods) function for each endpoint
 *      in the route's `+page.server.ts`.
 *      A consequence is the query parameters passed to the 
 *      redirect Uri are displayed in the address bar, as the response
 *      is to the redirect to the redirect Uri.
 *    - saveInSessionAndRedirect` same as `saveInSessionAndLoad` except that 
 *      a redirect is done to the `authorizedUrl`.  Instead of using the `load`
 *      or `actions` method in a `+page.server.ts`, you should use the `get` 
 *      or `post` method in a `+server.ts`.
 *    - `sendInPage` same as `saveinSessionAndLoad` except the tokens are
 *      not saved in the session.  Use the `load`/`actions` function in your
 *      `+page.server.ts`.
 *    - `custom` the function in 
 *       {@link FastifyOAuthClientOptions.receiveTokenFn} is called.  Use
 *       `get` or `load` depending on whether your function is returning
 *       a Response or object.
 *      
 * **{@link FastifyOAuthClientOptions.errorResponseType}**
 * 
 *    - `sendJson` a JSON response is sent with fields
 *       `status`, `errorMessage`,
 *      `errorMessages` and `errorCodeName`.
 *    - `svelteKitError` calls the SvelteKit `error` function (the one
 *      provided in the options to {@link SvelteKitServe}).
 *    - `custom` {@link SvelteKitOAuthClientOptions.errorFn} is called.
 * 
 *    Note that this parameter is only used when you are using the `get`
 *    endpoints, not the `load` ones.  The latter return the error in 
 *    the PageData from the load.
 * 
 * **Backend-for-Frontend (BFF)**
 * 
 * This class supports the backend-for-frontend (BFF) model.  You create an
 * endpoint for every resource server endpoint you want to be able to call, by
 * setting them in {@link SvelteKitOAuthClientOptions.bffEbdpoints}.  You set the
 * {@link SvelteKitOAuthClientOptions.tokenResponseType} to `saveInSessionAndLoad`
 * or `saveInSessionAndRedirect` so that tokens are saved in the session.  
 * You also set `bffBaseUrl` to the base URL of the resource server.
 * When you want to call a resource server endpoint, you call
 * `bffEndpointName` + *`url`*. The client will
 * pull the access token from the session, put it in the `Authorization` header
 * and called `bffBaseUrl` + *`url`* using fetch, and return the
 * response verbatim.  
 * 
 * This pattern avoids you having to store the access token in the frontend.
 * 
 * **Endpoints provided by this class**
 * 
 * In addition to the BFF endpoints above, which are implemented in the hook,
 * this class provides the following 
 * endpoints. As noted above, you should either use the endpoint's `load`
 * or `get`/`put` depending on the value of `tokenResponseType`. 
 */
export class SvelteKitOAuthClient extends OAuthClientBackend {
    server : SvelteKitServer;
    sessionDataName : string = "oauth";
    private receiveTokenFn : 
        ( oauthResponse: OAuthTokenResponse,
            client: SvelteKitOAuthClient,
            event : RequestEvent) 
            => Promise<Response|TokenReturn|undefined> = sendJson;
    readonly errorFn : SvelteKitErrorFn = jsonError;
    private loginUrl : string = "/login";
    authorizedUrl : string = "";

    readonly redirect : any;
    readonly error : any;

    /** 
     * See {@link FastifyOAuthClientOptions}
     */
    loginProtectedFlows : string[] = [];
    private tokenResponseType :  
        "sendJson" | 
        "saveInSessionAndLoad" | 
        "saveInSessionAndRedirect" | 
        "sendInPage" | 
        "custom" = "sendJson";
    private errorResponseType :  
        "sendJson" | 
        "svelteKitError" | 
        "custom" = "sendJson";
    private bffEndpoints: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[],
        matchSubUrls?: boolean
        }[] = [];
    private bffEndpointName = "bff";
    private bffBaseUrl? : string;
    private tokenEndpoints : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh"|"have_id")[] = [];
    
    /**
     * Constructor
     * @param server the {@link FastifyServer} instance
     * @param authServerBaseUrl the `iss` claim in the access token must match this value
     * @param options See {@link FastifyOAuthClientOptions}
     */
    constructor(server: SvelteKitServer,
        authServerBaseUrl: string,
        options: SvelteKitOAuthClientOptions) {
        super(authServerBaseUrl, options);
        this.server = server;
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("loginProtectedFlows", ParamType.JsonArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        setParameter("bffEndpointName", ParamType.String, this, options, "OAUTH_BFF_ENDPOINT_NAME");
        setParameter("bffBaseUrl", ParamType.String, this, options, "OAUTH_BFF_BASEURL");
        setParameter("redirectUri", ParamType.String, this, options, "OAUTH_REDIRECTURI", true);
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL", false);

        if (options.redirect) this.redirect = options.redirect;
        if (options.error) this.error = options.error;        

        try {
            new URL(this.redirectUri ?? "");
        } catch (e) {
            throw new CrossauthError(ErrorCode.Configuration, "Invalid redirect Uri " + this.redirectUri);
        }

        if (options.tokenEndpoints) this.tokenEndpoints = options.tokenEndpoints;

        if (this.bffEndpointName.endsWith("/")) this.bffEndpointName = this.bffEndpointName.substring(0, this.bffEndpointName.length-1);
        if (options.bffEndpoints) this.bffEndpoints = options.bffEndpoints;

        if (this.loginProtectedFlows.length == 1 && 
            this.loginProtectedFlows[0] == OAuthFlows.All) {
            this.loginProtectedFlows = this.validFlows;
        } else {
            if (!OAuthFlows.areAllValidFlows(this.loginProtectedFlows)) {
                throw new CrossauthError(ErrorCode.Configuration,
                        "Invalid flows specificied in " + this.loginProtectedFlows.join(","));
            }
        }

        if (this.tokenResponseType == "custom" && !options.receiveTokenFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Token response type of custom selected but receiveTokenFn not defined");
        }
        if (this.tokenResponseType == "custom" && options.receiveTokenFn) {
            this.receiveTokenFn = options.receiveTokenFn;
        } else if (this.tokenResponseType == "sendJson") {
            this.receiveTokenFn = sendJson;
        } else if (this.tokenResponseType == "sendInPage") {
            this.receiveTokenFn = sendInPage;
        } else if (this.tokenResponseType == "saveInSessionAndLoad") {
            this.receiveTokenFn = sendJson; saveInSessionAndLoad;
        } else if (this.tokenResponseType == "saveInSessionAndRedirect") {
            this.receiveTokenFn = saveInSessionAndRedirect;
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.authorizedUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must provide authorizedUrl");
        }
        if ((this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "saveInSessionAndRedirect") &&
            this.server.sessionServer == undefined) {
            throw new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is" + this.tokenResponseType + ", must activate the session server");
        }
        if (this.errorResponseType == "custom" && !options.errorFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "sendJson") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "svelteKitError") {
            this.errorFn = svelteKitError;
        }

        if (!options.redirect) throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit redirect function");
        if (!options.error && this.errorResponseType == "svelteKitError") throw new CrossauthError(ErrorCode.Configuration, "Must provide the SvelteKit error function");

        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, 
                "loginUrl must be set if protecting oauth endpoints");
        }
    }       

    private async passwordPost(event : RequestEvent, formData: {[key:string]:string}) : Promise<OAuthTokenResponse> {

        try {
            let resp = 
                await this.passwordFlow(formData.username,
                    formData.password,
                    formData.scope);
            if (resp.error == "mfa_required" && 
                resp.mfa_token &&
                this.validFlows.includes(OAuthFlows.PasswordMfa)) {
                const mfa_token = resp.mfa_token;
                resp = await this.passwordMfa(mfa_token,
                    formData.scope,
                    event);
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                        throw ce;
                    }
                //return await this.receiveTokenFn(resp, this, event);
                return resp;
               
            } else if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, 
                    resp.error_description);
                    throw ce;
            }
            //return await this.receiveTokenFn(resp, this, event);
            return resp;
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: event.locals.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };            
        }
    }

    private async passwordMfa(
        mfa_token: string,
        scope : string|undefined,
        _event: RequestEvent,
    ) : Promise<OAuthTokenResponse> {

        const authenticatorsResponse = 
            await this.mfaAuthenticators(mfa_token);
            if (authenticatorsResponse.error || 
            !authenticatorsResponse.authenticators ||
            !Array.isArray(authenticatorsResponse.authenticators) ||
            authenticatorsResponse.authenticators.length == 0 ||
            (authenticatorsResponse.authenticators.length > 1 && 
                !authenticatorsResponse.authenticators[0].active )) {
                    return {
                        error: authenticatorsResponse.error ?? "server_error",
                        error_description: authenticatorsResponse.error_description ?? "Unexpected error getting MFA authenticators",
                    };                    
                }

        const auth = authenticatorsResponse.authenticators[0] as MfaAuthenticatorResponse;
        if (auth.authenticator_type == "otp") {
            const resp = await this.mfaOtpRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="otp") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OTP challenge");
                CrossauthLogger.logger.debug({err: ce});
                CrossauthLogger.logger.error({cerr: ce});
                return {
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            return {
                scope: scope,
                mfa_token: mfa_token,
            };            
        } else if (auth.authenticator_type == "oob") {
            const resp = await this.mfaOobRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="oob" || !resp.oob_code || 
                resp.binding_method != "prompt") {
                const ce = CrossauthError.fromOAuthError(resp.error??"server_error",
                    resp.error_description??"Invalid response from MFA OOB challenge");
                    CrossauthLogger.logger.debug({err: ce});
                    CrossauthLogger.logger.error({cerr: ce});
                    return {
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                
            }

            return {
                scope: scope,
                mfa_token: mfa_token,
                oob_channel: auth.oob_channel,
                challenge_type: resp.challenge_type,
                binding_method: resp.binding_method,
                oob_code: resp.oob_code,
                name: auth.name,
            };
        }

        const ce = new CrossauthError(ErrorCode.UnknownError, 
            "Unsupported MFA type " + auth.authenticator_type + " returned");
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
        };                    
    }

    private async passwordOtp(
        _event: RequestEvent,
        formData: {[key:string]:string}
    ) : Promise<OAuthTokenResponse> {

        const resp = await this.mfaOtpComplete(formData.mfa_token, 
            formData.otp);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };                    
        }
        //return await this.receiveTokenFn(resp, this, event);
        return resp;
    }

    private async passwordOob(
        event: RequestEvent,
        formData: {[key:string]:string}
    ) : Promise<OAuthTokenResponse> {

        const resp = await this.mfaOobComplete(formData.mfa_token, 
            formData.oob_code,
            formData.binding_code);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                cerr: ce,
                user: event.locals.user?.user,
                hashedMfaToken: Crypto.hash(formData.mfa_token),
            }));
            CrossauthLogger.logger.debug(j({err: ce}));
            return {
                error: ce.oauthErrorCode,
                error_description: ce.message,
            };                    
        }
        //return await this.receiveTokenFn(resp, this, event);
        return resp;
    }

    async refresh(silent: boolean, event: RequestEvent,
        onlyIfExpired : boolean,
        refreshToken?: string,
        expiresAt?: number) 
        : Promise<{
            success: boolean,
            refresh_token?: string,
            access_token?: string,
            expires_in?: number,
            expires_at?: number,
            error?: string,
            error_description?: string
        }|undefined> {
            if (!expiresAt || !refreshToken) {
                return undefined;
            }

        if (!onlyIfExpired || expiresAt <= Date.now()) {
            try {
                const resp = await this.refreshTokenFlow(refreshToken);
                if (!resp.error && !resp.access_token) {
                    resp.error = "server_error";
                    resp.error_description = "Unexpectedly did not receive error or access token";
                }
                if (!resp.error) {
                    /*const resp1 = await this.receiveTokenFn(resp,
                        this,
                        request,
                        silent ? undefined : reply);
                    if (!silent) return resp1;*/
                    return {success: true, ...resp};
                } 
                if (!silent) {
                    const ce = CrossauthError.fromOAuthError(resp.error??"server_error", 
                        resp.error_description);
                        return {
                            success: false,
                            error: ce.oauthErrorCode,
                            error_description: ce.message,
                        };                    
                    }
                let expires_in = resp.expires_in;
                if (!expires_in && resp.access_token) {
                    const payload = jwtDecode(resp.access_token);
                    if (payload.exp) expires_in = payload.exp;
                }
                if (!expires_in) {
                    throw new CrossauthError(ErrorCode.BadRequest, 
                        "OAuth server did not return an expiry for the access token");
                }
                const expires_at = 
                    (new Date().getTime() + (expires_in*1000));
                return {
                    success: true,
                    access_token: resp.access_token,
                    refresh_token: resp.refresh_token,
                    expires_in: resp.expires_in,
                    expires_at: expires_at,
                    error: resp.error,
                    error_description: resp.error_description
                };
            } catch(e) {
                CrossauthLogger.logger.debug(j({err: e}));
                CrossauthLogger.logger.error(j({
                    cerr: e,
                    msg: "Failed refreshing access token"
                }));
                if (!silent) {
                    const ce = CrossauthError.asCrossauthError(e);
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    };                    
                }

                return {
                    success: false,
                    error:  "server_error",
                    error_description: "Failed refreshing access token",
                };                    

            }
        }
        return undefined;
    }

    // TODO: can only call if sessions enabled?
    private async refreshTokens(event : RequestEvent,
        silent: boolean,
        onlyIfExpired : boolean,
        csrfToken : string|undefined) {
        if (!csrfToken) {
            return {
                error: "access_denied",
                error_description: "No CSRF token given"
            }; // TODO: check this becfre calling - is better
        }
        const oauthData = await this.server.sessionServer?.getSessionData(event, "oauth");
        if (!oauthData?.refresh_token) {
            if (silent) {
                return {};
            } else {
                const ce = new CrossauthError(ErrorCode.InvalidSession,
                    "No tokens found in session");
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                    exception: ce
                }
            }
        }

        const resp = 
            await this.refresh(silent, event,
                onlyIfExpired,
                oauthData.refresh_token,
                //onlyIfExpired ? oauthData.expires_at : undefined
                oauthData.expires_at
            );
        if (!silent) {
            if (resp == undefined) return this.receiveTokenFn({}, this, event);
            if (resp != undefined) return resp; // XXX
        }
        return {
            success: true,
            expires_at: resp?.expires_at,
        }
    };

    
    ////////////////////////////////////////////////////////////////
    // Endpoints

    readonly authorizationCodeFlowEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                const scope = event.url.searchParams.get("scope") ?? undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, event, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        load: async (event : RequestEvent) : Promise<AuthorizationCodeFlowReturn> => {
            if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                const scope = event.url.searchParams.get("scope") ?? undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }
                CrossauthLogger.logger.debug(j({
                    msg: `Authorization code flow: redirecting`,
                    url: url
                }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },

    };

    readonly authorizationCodeFlowWithPKCEEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                const scope = event.url.searchParams.get("scope") ?? undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope, true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, event, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
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

        load: async (event : RequestEvent) : Promise<AuthorizationCodeFlowReturn> => {
            if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use get not load");
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flow is not supported");
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                    }

                if (!event.locals.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }          
                const scope = event.url.searchParams.get("scope") ?? undefined;
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(scope, true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                        return {
                            success: false,
                            error: ce.oauthErrorCode,
                            error_description: ce.message,
                        }
                        }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                throw this.redirect(302, url);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },
    };

    readonly redirectUriEndpoint = {

        get: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use load not get");
                return this.errorFn(this.server, event, ce);
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
                    this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
                    this.validFlows.includes(OAuthFlows.OidcAuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flows are not supported");
                    return this.errorFn(this.server, event, ce);
                }

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }    
                
                const code = event.url.searchParams.get("code") ?? "";
                const state = event.url.searchParams.get("state") ?? undefined;
                const error = event.url.searchParams.get("error") ?? undefined;
                const error_description = event.url.searchParams.get("error") ?? undefined;
                const resp =  await this.redirectEndpoint(code,
                    state,
                    error,
                    error_description);
                if (resp.error) return this.errorFn(this.server, event, CrossauthError.fromOAuthError(resp.error, resp.error_description));

                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return await this.errorFn(this.server,
                        event,
                        ce);
                }
                return await this.receiveTokenFn(resp, this, event);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        load: async (event : RequestEvent) : Promise<RedirectUriReturn> => {
            if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use get not load");
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }
            }
            try {

                if (!(this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
                    this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
                    this.validFlows.includes(OAuthFlows.OidcAuthorizationCode))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Authorization flows are not supported");
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    throw this.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(event.request.url));
                }    
                
                const code = event.url.searchParams.get("code") ?? "";
                const state = event.url.searchParams.get("state") ?? undefined;
                const error = event.url.searchParams.get("error") ?? undefined;
                const error_description = event.url.searchParams.get("error") ?? undefined;
                const resp =  await this.redirectEndpoint(code,
                    state,
                    error,
                    error_description);
                if (resp.error) return {
                    success: false,
                    error: resp.error,
                    error_description: resp.error_description,
                }


                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return {
                        success: false,
                        error: ce.oauthErrorCode,
                        error_description: ce.message,
                    }
                }
                const receiveTokenResp = await this.receiveTokenFn(resp, this, event);
                if (receiveTokenResp instanceof Response) return {
                    success: false,
                    error: "server_error",
                    error_description: "When using load, receiveTokenFn should return an object not a Response",

                };
                if (receiveTokenResp == undefined) return {
                    success: false,
                    error: "server_error",
                    error_description: "No response received from receiveTokenFn",

                };
                if (receiveTokenResp.error) return {
                    success: false,
                    error: receiveTokenResp.error,
                    error_description: receiveTokenResp.error_description,

                }
                return {
                    success: true,
                    ...receiveTokenResp,
                }

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return {
                    success: false,
                    error: ce.oauthErrorCode,
                    error_description: ce.message,
                }

            }
        },
    };

    readonly clientCredentialsFlowEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            let formData : {[key:string]:string}|undefined = undefined;
            try {

                if (!(this.validFlows.includes(OAuthFlows.ClientCredentials))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Client credentials flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return this.error(401, "Must log in to use client credentials");
                }    
                
                const resp = await this.clientCredentialsFlow(formData?.scope);
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    return await this.errorFn(this.server,
                        event,
                        ce);
                }
                return await this.receiveTokenFn(resp, this, event);

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }

                let formData : {[key:string]:string}|undefined = undefined;
                try {
    
                    if (!(this.validFlows.includes(OAuthFlows.ClientCredentials))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Client credentials flow is not supported");
                        throw ce;
                    }
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
    
                    if (!event.locals.user && 
                        (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                            return {
                                success: false,
                                error: "access_denied",
                                error_description: "Must log in to use client credentials flow" ,
                            }
                        }    
                    
                    const resp = await this.clientCredentialsFlow(formData?.scope);
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        throw ce;
                    }
                    return await this.receiveTokenFn(resp, this, event) ?? {};
    
                } catch (e) {
                    if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    if (SvelteKitServer.isSvelteKitError(e)) throw e;
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug({err: e});
                    CrossauthLogger.logger.error({cerr: e});
                    //throw this.error(ce.httpStatus, ce.message);
                    return { 
                        success: false,
                        error: ce.oauthErrorCode, 
                        error_description: ce.message
                    };
    
                }
    
            }        
        }
    };

    readonly refreshTokenFlowEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            let formData : {[key:string]:string}|undefined = undefined;
            try {

                if (!(this.validFlows.includes(OAuthFlows.RefreshToken))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Refresh token flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");

                    return this.errorFn(this.server, event, ce);
                }    

                // if the session server and CSRF protection enabled, require a valid CSRF token
                if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                    try {
                        const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                        if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                   }
                   catch (e) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");
                        return this.errorFn(this.server, event, ce);
                   }
    
                }

                // get refresh token from body if present, otherwise
                // try to find in session
                let refreshToken : string | undefined = formData.refresh_token;
                if (!refreshToken && this.server.sessionServer) {
                    const oauthData = await this.server.sessionServer.getSessionData(event, "oauth");
                    if (!oauthData?.refresh_token) {
                        const ce = new CrossauthError(ErrorCode.BadRequest,
                            "No refresh token in session or in parameters");
                        return this.errorFn(this.server, event, ce);
                    }
                    refreshToken = oauthData.refresh_token;
                } 
                if (!refreshToken) {
                    // TODO: refresh token cookie - call with no refresh token?
                    const ce = new CrossauthError(ErrorCode.BadRequest,
                        "No refresh token supplied");
                    return this.errorFn(this.server, event, ce);
                }

                const resp = 
                    await this.refreshTokenFlow(refreshToken);
            
                const resp2 = await this.receiveTokenFn(resp, this, event) ;
                if (resp && resp2 instanceof Response) return resp2;
                throw new CrossauthError(ErrorCode.UnknownError, "Receive token function did not return a Response");

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }

                let formData : {[key:string]:string}|undefined = undefined;
                try {
    
                    if (!(this.validFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Refresh token flow is not supported");
                        return this.errorFn(this.server, event, ce);
                    }
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
    
                    if (!event.locals.user && 
                        (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token");
                        throw ce;
                    }    
                    
                    // if the session server and CSRF protection enabled, require a valid CSRF token
                    if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                        try {
                            const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                            if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                    }
                    catch (e) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");
                        throw ce;
                    }
        
                    }

                    // get refresh token from body if present, otherwise
                    // try to find in session
                    let refreshToken : string | undefined = formData.refresh_token;
                    if (!refreshToken && this.server.sessionServer) {
                        const oauthData = await this.server.sessionServer.getSessionData(event, "oauth");
                        if (!oauthData?.refresh_token) {
                            const ce = new CrossauthError(ErrorCode.BadRequest,
                                "No refresh token in session or in parameters");
                            throw ce;
                        }
                        refreshToken = oauthData.refresh_token;
                    } 
                    if (!refreshToken) {
                        // TODO: refresh token cookie - call with no refresh token?
                        const ce = new CrossauthError(ErrorCode.BadRequest,
                            "No refresh token supplied");
                        throw ce;
                    }

                    const resp = 
                        await this.refreshTokenFlow(refreshToken);

                    const resp2 = await this.receiveTokenFn(resp, this, event) ?? {};
                    if (resp2 instanceof Response) throw new CrossauthError(ErrorCode.Configuration, "Refresh token flow should return an object not Response");
                    return resp2;

                } catch (e) {
                    if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    if (SvelteKitServer.isSvelteKitError(e)) throw e;
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug({err: e});
                    CrossauthLogger.logger.error({cerr: e});
                    //throw this.error(ce.httpStatus, ce.message);
                    return { 
                        success: false,
                        error: ce.oauthErrorCode, 
                        error_description: ce.message
                    };
    
                }
    
            }        
        }
    };

    readonly passwordFlowEndpoint = {

        post: async (event : RequestEvent) => {
            if (this.tokenResponseType == "saveInSessionAndLoad" || this.tokenResponseType == "sendInPage") {
                const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use actions not post");
                return this.errorFn(this.server, event, ce);
            }
            let formData : {[key:string]:string}|undefined = undefined;
            try {

                if (!(this.validFlows.includes(OAuthFlows.Password) ||
                    this.validFlows.includes(OAuthFlows.PasswordMfa))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Password flow is not supported");
                    return this.errorFn(this.server, event, ce);
                }
                var data = new JsonOrFormData();
                await data.loadData(event);
                formData = data.toObject();

                if (!event.locals.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.Password) ||
                    this.loginProtectedFlows.includes(OAuthFlows.PasswordMfa))) {
                    const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use password flow");

                    return this.errorFn(this.server, event, ce);
                }    

                // if the session server and CSRF protection enabled, require a valid CSRF token
                if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                    try {
                        const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                        if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                   }
                   catch (e) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");
                        return this.errorFn(this.server, event, ce);
                   }
    
                }

                const resp = 
                    await this.passwordPost(event, formData);
                if (!resp) throw new CrossauthError(ErrorCode.UnknownError, "Password flow returned no data");
                const resp2 = await this.receiveTokenFn(resp, this, event) ;
                if (resp && resp2 instanceof Response) return resp2;
                throw new CrossauthError(ErrorCode.UnknownError, "Receive token function did not return a Response");

            } catch (e) {
                if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                if (SvelteKitServer.isSvelteKitError(e)) throw e;
                const ce = CrossauthError.asCrossauthError(e);
                CrossauthLogger.logger.debug({err: e});
                CrossauthLogger.logger.error({cerr: e});
                //throw this.error(ce.httpStatus, ce.message);
                return this.errorFn(this.server, event, ce);

            }
        },

        actions: {
            default: async ( event : RequestEvent ) => {
                if (this.tokenResponseType == "saveInSessionAndRedirect" || this.tokenResponseType == "sendJson") {
                    const ce = new CrossauthError(ErrorCode.Configuration, "If tokenResponseType is " + this.tokenResponseType + ", use post not load");
                    throw ce;
                }

                let formData : {[key:string]:string}|undefined = undefined;
                try {
    
                    if (!(this.validFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Refresh token flow is not supported");
                        return this.errorFn(this.server, event, ce);
                    }
                    var data = new JsonOrFormData();
                    await data.loadData(event);
                    formData = data.toObject();
    
                    if (!event.locals.user && 
                        (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                        const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token");
                        throw ce;
                    }    
                    
                    // if the session server and CSRF protection enabled, require a valid CSRF token
                    if (this.server.sessionServer && this.server.sessionServer.enableCsrfProtection) {
                        try {
                            const cookieValue = this.server.sessionServer.getCsrfCookieValue(event);
                            if (cookieValue) this.server.sessionServer.sessionManager.validateCsrfCookie(cookieValue);
                        }
                        catch (e) {
                            const ce = new CrossauthError(ErrorCode.Unauthorized, "Must log in to use refresh token flow");
                            throw ce;
                        }
        
                    }

                    const resp = 
                        await this.passwordPost(event, formData);
                    if (!resp) throw new CrossauthError(ErrorCode.UnknownError, "Password flow returned no data");

                    const resp2 = await this.receiveTokenFn(resp, this, event) ?? {};
                    if (resp2 instanceof Response) throw new CrossauthError(ErrorCode.Configuration, "Refresh token flow should return an object not Response");
                    return resp2;
                    
                } catch (e) {
                    if (SvelteKitServer.isSvelteKitRedirect(e)) throw e;
                    if (SvelteKitServer.isSvelteKitError(e)) throw e;
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug({err: e});
                    CrossauthLogger.logger.error({cerr: e});
                    //throw this.error(ce.httpStatus, ce.message);
                    return { 
                        success: false,
                        error: ce.oauthErrorCode, 
                        error_description: ce.message
                    };
    
                }
    
            }        
        }
    };
}
