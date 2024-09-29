// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { jwtDecode } from "jwt-decode";
import QRCode from 'qrcode';
import { type FastifyRequest, type FastifyReply } from 'fastify';
import {
    CrossauthError,
    ErrorCode,
    CrossauthLogger,
    OAuthFlows,
    type OAuthTokenResponse,
    j, 
    type MfaAuthenticatorsResponse,
    MfaAuthenticatorResponse,
    type OAuthDeviceAuthorizationResponse,
    User} from '@crossauth/common';
import {
    setParameter,
    ParamType,
    Crypto,
    OAuthClientBackend } from '@crossauth/backend';
import type { OAuthClientOptions } from '@crossauth/backend';
import { FastifyServer, type FastifyErrorFn } from './fastifyserver';
import type { CsrfBodyType } from './fastifysession.ts';

const JSONHDR : [string,string] = 
    ['Content-Type', 'application/json; charset=utf-8'];

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

/**
 * Options for {@link FastifyOAuthClient}.
 */
export interface FastifyOAuthClientOptions extends OAuthClientOptions {

    /** The base URL for endpoints served by this class.
     * THe only endpoint that is created is the redirect Uri, which is
     * `siteUrl` + `prefix` + `authzcode`,
     */
    siteUrl ?: string,

    /**
     * The prefix between the `siteUrl` and endpoints created by this
     * class.  See {@link FastifyOAuthClientOptions.siteUrl}.
     */
    prefix? : string,

    /**
     * When using the BFF (backend-for-frontend) pattern, tokens are saved
     * in the `data` field of the session ID.  They are saved in the JSON
     * object with this field name.  Default `oauth`.
     */
    sessionDataName? : string,

    /**
     * The template file for rendering error messages
     * when {@link FastifyOAuthClientOptions.errorResponseType}
     * is `errorPage`.
     */
    errorPage? : string,

    /**
     * The template file for asking the user for username and password
     * in the password flow,
     * 
     * Default `passwordflow.njk`
     */
    passwordFlowPage? : string,

    /**
     * The template file to tell users the url to go to to complete the 
     * device code flow.
     * 
     * Default `devicecodeflow.njk`
     */
    deviceCodeFlowPage? : string,

    /**
     * The template file to show the result in the `deletetokens` endpoint.
     * 
     * Default `deletetokens.njk`
     */
    deleteTokensPage? : string,

    /**
     * Tthe `deletetokens` GET endpoint.
     * 
     * Default undefined - don't create the endpoint
     */
    deleteTokensGetUrl? : string,

    /**
     * Whether to add the `deletetokens` POST endpoint.
     * 
     * Default undefined - don't create the endpoint
     */
    deleteTokensPostUrl? : string,

    /**
     * Whether to add the `api/deletetokens` POST endpoint.
     * 
     * Default undefined - don't create the endpoint
     */
    apiDeleteTokensPostUrl? : string,

    /**
     * The template file for asking the user for an OTP in the password MFA
     * flow.
     */
    mfaOtpPage? : string,

    /**
     * The template file for asking the user for an OOB in the password MFA
     * flow.
     */
    mfaOobPage? : string,

    /**
     * The template file for telling the user that authorization was successful.
     */
    authorizedPage? : string,

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
     * The URL to create the password flow under.  Default `passwordflow`.
     */
    passwordFlowUrl? : string,

    /**
     * The URL to to create the device code flow under.  Default `devicecodeflow`.
     */
    deviceCodeFlowUrl? : string,

    /**
     * The URL to to for polling until the device code flow completes.  
     * Default `devicecodepoll`.
     */
    deviceCodePollUrl? : string,

    /**
     * The URL to create the otp endpoint for the password mfa flow under.  
     * This endpoint asks the user for his or her OTP.
     * Default `passwordflowotp`.
     */
    passwordOtpUrl? : string,

    /**
     * The URL to create the otp endpoint for the password mfa flow under.  
     * This endpoint asks the user for his or her OOB.
     * Default `passwordflowoob`.
     */
    passwordOobUrl? : string,

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
        client: FastifyOAuthClient,
        request: FastifyRequest,
        reply?: FastifyReply) => Promise<FastifyReply|undefined>;

    /**
     * The function to call when there is an OAuth error and
     * {@link FastifyOAuthClientOptions.errorResponseType}
     * is `custom`.
     * See {@link FastifyErrorFn}.
     */
    errorFn? :FastifyErrorFn;

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
        "errorPage" | 
        "custom",

    /** 
     * Array of resource server endppints to serve through the
     * BFF (backend-for-frontend) mechanism.
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    bffEndpoints?: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH")[],
        matchSubUrls?: boolean
    }[],

    /**
     * Prefix for BFF endpoints.  Default "bff".
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    bffEndpointName? : string,

    /**
     * Base URL for resource server endpoints called through the BFF
     * mechanism.
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    bffBaseUrl? : string,

    /**
     * Endpoints to provide to acces tokens through the BFF mechanism,
     * See {@link FastifyOAuthClient} class documentation for full description.
     */
    tokenEndpoints? : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh_token"|"have_id_token")[],

    /**
     * Set of flows to enable (see {@link @crossauth/common!OAuthFlows}).
     * 
     * Defaults to empty.
     */
    validFlows? : string[],

    /**
     * These token types will be treated as JWT.  Default all of them
     */
    jwtTokens?: ("access"|"id"|"refresh")[]
}


/////////////////////////////////////////////////////////////////////////////
// FASTIFY INTERFACES

/**
 * Query type for the `authorize` Fastify request.
 */
export interface ClientAuthorizeQueryType {
    scope? : string,
}

/**
 * Query type for the redirect Uri Fastify request.
 */
export interface RedirectUriQueryType {
    code? : string,
    state?: string,
    error? : string,
    error_description? : string,
}

/**
 * Query type for the password flow Fastify request.
 */
export interface PasswordQueryType {
    scope? : string,
}

/**
 * Query type for the client cresentials flow Fastify request.
 */
export interface ClientCredentialsBodyType {
    scope? : string,
    csrfToken? : string,
}

/**
 * Query type for the refresh token flow Fastify request.
 */
export interface RefreshTokenBodyType {
    refreshToken?: string,
    csrfToken? : string,
}

/**
 * Body type for the password flow Fastify request.
 */
export interface PasswordBodyType {
    username : string,
    password: string,
    scope? : string,
    csrfToken? : string,
}

export interface DeviceCodeFlowResponse extends OAuthDeviceAuthorizationResponse {
    user? : User,
    scope? : string,
    verification_uri_qrdata? : string,
    errorMessage? : string,
    errorCode? : number,
    errorCodeName? : string,
    csrfToken? : string,
}
/**
 * Body type for the device code flow Fastify request.
 */
export interface DeviceCodeBodyType {
    scope? : string,
    csrfToken? : string,
}

/**
 * Body type for the device code flow Fastify request.
 */
export interface DeviceCodePollBodyType {
    device_code : string,
    csrfToken? : string,
}

/**
 * Query type for the OTP endpoint on the password mfa flow Fastify request.
 */
export interface PasswordOtpType {
    scope? : string,
    mfa_token : string,
    otp : string,
    challenge_type? : string,
}

/**
 * Query type for the OOB endpoint on the password mfa flow Fastify request.
 */
export interface PasswordOobType {
    scope? : string,
    mfa_token : string,
    oob_code : string,
    binding_code : string,
    challenge_type? : string,
    name? : string,

}

/**
 * Query type for the refresh token flow Fastify request.
 */
export interface TokensBodyType {
    decode?: boolean,
    csrfToken? : string,
}

////////////////////////////////////////////////////////////////////////////
// DEFAULT FUNCTIONS

async function jsonError(_server: FastifyServer,
    _request: FastifyRequest,
    reply: FastifyReply,
    ce: CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return reply.header(...JSONHDR)
        .status(ce.httpStatus).send({
            ok: false,
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCode: ce.code,
            errorCodeName: ce.codeName
        });
}

async function pageError(server: FastifyServer,
    _request: FastifyRequest,
    reply: FastifyReply,
    ce: CrossauthError) : Promise<FastifyReply> {
    CrossauthLogger.logger.debug(j({err: ce}));
    return reply.status(ce.httpStatus)
        .view(server.oAuthClient?.errorPage ?? "error.njk", {
            status: ce.httpStatus,
            errorMessage: ce.message,
            errorMessages: ce.messages,
            errorCodeName: ce.codeName
        });
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
    client: FastifyOAuthClient,
    _request: FastifyRequest,
    reply?: FastifyReply) : Promise<FastifyReply|undefined> {
    if (reply) {
        let res : {[key:string]:any}= {ok: true, ...oauthResponse}
        if (client.jwtTokens.includes("id")) {
            res["id_payload"] = decodePayload(oauthResponse.id_token)
        }
        return reply.header(...JSONHDR).status(200).send(res);
    }
}

function logTokens(oauthResponse: OAuthTokenResponse, jwtTokens : string[]) {
    if (oauthResponse.access_token) {
        try {
            if (oauthResponse.access_token && jwtTokens.includes("access")) {
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
            if (oauthResponse.id_token && jwtTokens.includes("id")) {
                const jti = jwtDecode(oauthResponse.id_token)?.jti;
                const hash = jti ? Crypto.hash(jti) : undefined;
                CrossauthLogger.logger.debug(j({msg: "Got id token", 
                    idTokenHash: hash}));
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
        }
    }
    if (oauthResponse.refresh_token && jwtTokens.includes("refresh")) {
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

async function sendInPage(oauthResponse: OAuthTokenResponse,
    client: FastifyOAuthClient,
    _request: FastifyRequest,
    reply?: FastifyReply) : Promise<FastifyReply|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        if (reply) {
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                });
        }
    }

    logTokens(oauthResponse, client.jwtTokens);

    if (reply) {
        try {
            let resp : {[key:string]:any} = {...oauthResponse};
            if (client.jwtTokens.includes("id")) {
                resp["id_payload"] = decodePayload(oauthResponse.id_token);
            }
            return reply.status(200).view(client.authorizedPage, resp);
        } catch (e) {
            const ce =CrossauthError.asCrossauthError(e);
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName
                });
        }
    }
}

async function saveInSessionAndLoad(oauthResponse: OAuthTokenResponse,
    client: FastifyOAuthClient,
    request: FastifyRequest,
    reply?: FastifyReply,
    ) : Promise<FastifyReply|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        if (reply) {
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                });
            }
    }

    logTokens(oauthResponse, client.jwtTokens);
    try {

        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, request, reply);
        }

        if (reply) {
            if (!client.authorizedPage) {
                return reply.status(500)
                    .view(client.errorPage, {
                        status: 500,
                        errorMessage: "Authorized url not configured",
                        errorCodeName: ErrorCode[ErrorCode.Configuration],
                        errorCode: ErrorCode.Configuration
                    });
            }
            let resp : {[key:string]:any} = {...oauthResponse};
            if (client.jwtTokens.includes("id")) {
                resp["id_payload"] = decodePayload(oauthResponse.id_token);
            }
            return reply.status(200).view(client.authorizedPage, resp );
        }
    } catch (e) {
        const ce =CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        if (reply) {
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName
                });
        }
    }
}

async function updateSessionData(oauthResponse: OAuthTokenResponse,
    client: FastifyOAuthClient,
    request: FastifyRequest,
    reply?: FastifyReply,
    ) {
        if (!client.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot update session data if sessions not enabled");
        let expires_in = oauthResponse.expires_in;
        if (!expires_in && oauthResponse.access_token && client.jwtTokens.includes("access")) {
            const payload = jwtDecode(oauthResponse.access_token);
            if (payload.exp) expires_in = payload.exp;
        }
        if (!expires_in) {
            throw new CrossauthError(ErrorCode.BadRequest, 
                "OAuth server did not return an expiry for the access token");
        }
        const expires_at = Date.now() + (expires_in)*1000;
        let sessionData : {[key:string]:any}= {...oauthResponse, expires_at }
        if ("id_token" in oauthResponse) {
            let payload = decodePayload(oauthResponse["id_token"]);
            if (payload) sessionData["id_token"] = payload;
        }
        if (client.server.sessionServer) {
            // if we have a real session server, we can create an anonymous session
            // if there is no current session.  For session adapters, we assume
            // that a session was already created, or updateSessionData creates
            // one automatically.
            let sessionCookieValue =  client.server.sessionServer.getSessionCookieValue(request);
            if (!sessionCookieValue && reply) {
                sessionCookieValue = 
                    await client.server.createAnonymousSession(request,
                        reply,
                        { [client.sessionDataName]: sessionData });
    
            } else {
                // const existingData =  await client.server.sessionAdapter.getSessionData(request, client.sessionDataName);
                //await client.server.sessionAdapter.updateSessionData(request, client.sessionDataName, { ...existingData??{},  ...oauthResponse, expires_at });
                await client.server.sessionAdapter.updateSessionData(request, client.sessionDataName, sessionData);

            }

        } else /* No session server but might have session adapter */ {

            if (!client.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
                "Cannot get session data if sessions not enabled");
            //const existingData =  await client.server.sessionAdapter.getSessionData(request, client.sessionDataName);
            //await client.server.sessionAdapter.updateSessionData(request, client.sessionDataName, { ...existingData??{},  ...oauthResponse, expires_at });
            await client.server.sessionAdapter.updateSessionData(request, client.sessionDataName, sessionData);
        }

    }

async function saveInSessionAndRedirect(oauthResponse: OAuthTokenResponse,
    client: FastifyOAuthClient,
    request: FastifyRequest,
    reply?: FastifyReply,
    ) : Promise<FastifyReply|undefined> {
    if (oauthResponse.error) {
        const ce = CrossauthError.fromOAuthError(oauthResponse.error, 
            oauthResponse.error_description);
        if (reply) {
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName,
                    errorCode: ce.code
                });
        }
    }

    logTokens(oauthResponse, client.jwtTokens);

    try {
        if (oauthResponse.access_token || oauthResponse.id_token || oauthResponse.refresh_token) {
            await updateSessionData(oauthResponse, client, request, reply);
        }

        if (reply) {
            if (!client.authorizedUrl) {

                return reply.status(500)
                    .view(client.errorPage, {
                        status: 500,
                        errorMessage: "Authorized url not configured",
                        errorCodeName: ErrorCode[ErrorCode.Configuration],
                        errorCode: ErrorCode.Configuration
                    });

            }

            return reply.redirect(client.authorizedUrl);
        }
    } catch (e) {
        const ce =CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.debug(j({cerr: ce, msg: "Error receiving tokens"}));
        if (reply) {
            return reply.status(ce.httpStatus)
                .view(client.errorPage, {
                    status: ce.httpStatus,
                    errorMessage: ce.message,
                    errorCodeName: ce.codeName
                });
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// CLASSES

/**
 * The Fastify implementation of the OAuth client.
 * 
 * Makes requests to an authorization server, using a configurable set
 * of flows, which sends back errors or tokens,
 * 
 * When constructing this class, you define what happens with tokens that
 * are returned, or errors that are returned.  You do this with the
 * configuration options {@link FastifyOAuthClientOptions.tokenResponseType}
 * and {@link FastifyOAuthClientOptions.errorResponseType}.
 * 
 * **{@link FastifyOAuthClientOptions.tokenResponseType}**
 * 
 *   - `sendJson` the token response is sent as-is in the reply to the Fastify 
 *      request.  In addition to the `token` endpoint response fields,
 *      `ok: true` and `id_payload` with the decoded 
 *      payload of the ID token are retruned.
 *   - `saveInSessionAndLoad` the response fields are saved in the `data`
 *      field of the session ID in key storage.  In addition, `expires_at` is 
 *      set to the number of seconds since Epoch that the access token expires
 *      at.  After saving, page defined in `authorizedPage` is displayed.
 *      A consequence is the query parameters passed to the 
 *      redirect Uri are displayed in the address bar, as the response
 *      is to the redirect to the redirect Uri.
 *    - saveInSessionAndRedirect` same as `saveInSessionAndLoad` except that 
 *      a redirect is done to the `authorizedUrl` rather than displaying
 *      `authorizedPage` template.
 *    - `sendInPage` the `token` endpoint response is not saved in the session
 *      but just sent as template arguments when rendering the
 *      template in `authorizedPage`.  The JSON response fields are sent
 *      verbatim, with the additional fild of `id_payload` which is the
 *      decoded payload from the ID token, if present.
 *    - `custom` the function in 
 *       {@link FastifyOAuthClientOptions.receiveTokenFn} is called.
 *      
 * **{@link FastifyOAuthClientOptions.errorResponseType}**
 * 
 *    - `sendJson` a JSON response is sent with fields
 *       `status`, `errorMessage`,
 *      `errorMessages` and `errorCodeName`.
 *    - `errorPage` the template in {@link FastifyOAuthClientOptions.errorPage}
 *      is displayed with template parameters `status`, `errorMessage`,
 *      `errorMessages` and `errorCodeName`.
 *    - `custom` {@link FastifyOAuthClientOptions.errorFn} is called.
 * 
 * **Backend-for-Frontend (BFF)**
 * 
 * This class supports the backend-for-frontend (BFF) model.  You create an
 * endpoint for every resource server endpoint you want to be able to call, by
 * setting them in {@link FastifyOAuthClientOptions.bffEbdpoints}.  You set the
 * {@link FastifyOAuthClientOptions.tokenResponseType} to `saveInSessionAndLoad`
 * or `saveInSessionAndRedirect` so that tokens are saved in the session.  
 * You also set `bffBaseUrl` to the base URL of the resource server.
 * When you want to call a resource server endpoint, you call
 * `siteUrl` + `prefix` + `bffEndpointName` + *`url`*. The client will
 * pull the access token from the session, put it in the `Authorization` header
 * and called `bffBaseUrl` + *`url`* using fetch, and return the
 * response verbatim.  
 * 
 * This pattern avoids you having to store the access token in the frontend.
 * 
 *  **Middleware**
 *
 *  This class provides middleware that works with the BFF method.
 *
 *  If an ID token is saved in the session and it is valid, the following
 *  state attributes are set in the request object:
 *
 *     - `idPayload` the payload from the ID token
 *     - `user` a :class:`crossauth_backend.User` object created from the ID
 *        token
 *     - `authType` set to `oidc`
 *
 *  **Endpoints provided by this class**
 * 
 * In addition to the BFF endpoints above, this class provides the following 
 * endpoints. The ENDPOINT column values can be overridden in 
 * {@link FastifyOAuthClientOptions}. 
 * All POST endpoints also require `csrfToken`.
 * The Flow endpoints are only enabled if the corresponding flow is set
 * in {@link FastifyOAuthClientOptions.validFlows}. 
 * Token endpoints are only enabled if the corresponding endpoint is set
 * in {@link FastifyOAuthClientOptions.tokenEndpoints}. 
 * 
 * | METHOD | ENDPOINT            |Description                                                   | GET/BODY PARAMS                                     | VARIABLES PASSED/RESPONSE                                 | FILE                     |
 * | ------ | --------------------| ------------------------------------------------------------ | --------------------------------------------------- | --------------------------------------------------------- | ------------------------ |
 * | GET    | `authzcode`         | Redirect URI for receiving authz code                        | *See OAuth authorization code flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
 * | GET    | `passwordflow`      | Displays page to request username/password for password flow | scope                                               | user, scope                                               | passwordFlowPage         | 
 * | POST   | `passwordflow`      | Initiates the password flow                                  | *See OAuth password flow spec*                      | *See docs for`tokenResponseType`*                         |                          | 
 * |        |                     | Requests an OTP from the user for the Password MFA OTP flow  | `mfa_token`, `scope`, `otp`                         | `mfa_token`, `scope`, `error`, `errorMessage`             | mfaOtpPage               | 
 * |        |                     | Requests an OOB from the user for the Password MFA OOB flow  | `mfa_token`, `oob_code`, `scope`, `oob`             | `mfa_token`, `oob_code`, `scope`, `error`, `errorMessage` | mfaOobPage               | 
 * | POST   | `passwordotp`       | Token request with the MFA OTP                               | *See Password MFA flow spec*                        | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `passwordoob`       | Token request with the MFA OOB                               | *See Password MFA flow spec*                        | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `authzcodeflow`     | Initiates the authorization code flow                        | *See OAuth authorization code flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `authzcodeflowpkce` | Initiates the authorization code flow with PKCE              | *See OAuth authorization code flow with PKCE spec*  | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `clientcredflow`    | Initiates the client credentials flow                        | *See OAuth client credentials flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `refreshtokenflow`  | Initiates the refresh token flow                             | *See OAuth refresh token flow spec*                 | *See docs for`tokenResponseType`*                         |                          | 
 * | POST   | `devicecodeflow`    | Initiates the device code flow                               | See {@link DeviceCodeBodyType}                      | See {@link DeviceCodeFlowResponse}                        | `deviceCodeFlowPage`     | 
 * | POST   | `api/devicecodeflow` | Initiates the device code flow                              | See {@link DeviceCodeBodyType}                      | See {@link DeviceCodeFlowResponse}                        |                          | 
 * | POST   | `devicecodepoll`     | Initiates the device code flow                              | See {@link DeviceCodePollBodyType}                  | Authorization complete: See docs for`tokenResponseType`.  Other cases, {@link @crossauth/common!OAuthTokenResponse} |                          | 
 * | POST   | `api/devicecodepoll` | Initiates the device code flow                              | See {@link DeviceCodePollBodyType}                  | {@link @crossauth/common!OAuthTokenResponse}              |                          | 
 * | POST   | `access_token`      | For BFF mode, returns the saved access token                 | `decode`, default `true`                            | *Access token payload*                                    |                          | 
 * | POST   | `refresh_token`     | For BFF mode, returns the saved refresh token                | `decode`, default `true`                            | `token` containing the refresh token                      |                          | 
 * | POST   | `id_token     `     | For BFF mode, returns the saved ID token                     | `decode`, default `true`                            | *ID token payload*                                        |                          | 
 * | POST   | `have_access_token` | For BFF mode, returns whether an acccess token is saved      |                                                     | `ok`                                                      |                          | 
 * | POST   | `have_refresh_token`| For BFF mode, returns whether a refresh token is saved       |                                                     | `ok`                                                      |                          | 
 * | POST   | `have_id_token`     | For BFF mode, returns whether an ID token is saved           |                                                     | `ok`                                                      |                          | 
 * | POST   | `tokens`            | For BFF mode, returns all the saved tokens                   | `decode`, default `true`                            | *Token payloads      *                                    |                          | 
 * | POST   | `deletetokens`      | Deletes all BFF tokens and displays a page                   | None                                                | `ok`                                                      | `deleteTokensPage`       | 
 * | POST   | `api/deletetokens`  | Delertes all tokens and returns JSON                         | None                                                | `ok`                                                      |                          | 
 */
export class FastifyOAuthClient extends OAuthClientBackend {
    server : FastifyServer;
    private siteUrl : string = "/";
    private prefix : string = "/";
    errorPage : string = "error.njk";
    passwordFlowPage : string = "passwordflow.njk"
    deviceCodeFlowPage : string = "devicecodeflow.njk"
    deleteTokensPage : string = "deletetokens.njk"
    deleteTokensGetUrl : string|undefined = undefined;
    deleteTokensPostUrl : string|undefined = undefined;
    apiDeleteTokensPostUrl : string|undefined = undefined;
    mfaOtpPage : string = "mfaotp.njk"
    mfaOobPage : string = "mfaoob.njk"
    authorizedPage : string = "authorized.njk";
    authorizedUrl : string = "authorized";
    sessionDataName : string = "oauth";
    private receiveTokenFn : 
        ( oauthResponse: OAuthTokenResponse,
            client: FastifyOAuthClient,
            request: FastifyRequest,
            reply?: FastifyReply) 
            => Promise<FastifyReply|undefined> = sendJson;
    private errorFn : FastifyErrorFn = jsonError;
    private loginUrl : string = "/login";
    private validFlows : string[] = [];
    readonly jwtTokens : string[] = ["access", "id", "refresh"]
    private testMiddleware = false;
    // @ts-ignore
    private requestObj : FastifyRequest|undefined = undefined; 

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
        "jsonError" | 
        "pageError" | 
        "custom" = "jsonError";
    private passwordFlowUrl : string = "passwordflow";
    private passwordOtpUrl : string = "passwordotp";
    private passwordOobUrl : string = "passwordoob";
    private deviceCodeFlowUrl : string = "devicecodeflow";
    private deviceCodePollUrl : string = "devicecodepoll";
    private bffEndpoints: {
        url: string,
        methods: ("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD")[],
        matchSubUrls?: boolean
        }[] = [];
    private bffEndpointName = "bff";
    private bffBaseUrl? : string;
    private tokenEndpoints : ("access_token"|"refresh_token"|"id_token"|
        "have_access_token"|"have_refresh_token"|"have_id_token")[] = [];

    /**
     * Constructor
     * @param server the {@link FastifyServer} instance
     * @param authServerBaseUrl the `iss` claim in the access token must match this value
     * @param options See {@link FastifyOAuthClientOptions}
     */
    constructor(server: FastifyServer,
        authServerBaseUrl: string,
        options: FastifyOAuthClientOptions) {
        super(authServerBaseUrl, options);
        this.server = server;
        setParameter("sessionDataName", ParamType.String, this, options, "OAUTH_SESSION_DATA_NAME");
        setParameter("siteUrl", ParamType.String, this, options, "SITE_URL", true);
        setParameter("tokenResponseType", ParamType.String, this, options, "OAUTH_TOKEN_RESPONSE_TYPE");
        setParameter("errorResponseType", ParamType.String, this, options, "OAUTH_ERROR_RESPONSE_TYPE");
        setParameter("prefix", ParamType.String, this, options, "PREFIX");
        if (!(this.prefix.endsWith("/"))) this.prefix += "/";
        setParameter("loginUrl", ParamType.String, this, options, "LOGIN_URL");
        setParameter("errorPage", ParamType.String, this, options, "ERROR_PAGE");
        setParameter("authorizedPage", ParamType.String, this, options, "AUTHORIZED_PAGE");
        setParameter("authorizedUrl", ParamType.String, this, options, "AUTHORIZED_URL");
        setParameter("loginProtectedFlows", ParamType.JsonArray, this, options, "OAUTH_LOGIN_PROTECTED_FLOWS");
        setParameter("passwordFlowUrl", ParamType.String, this, options, "OAUTH_PASSWORD_FLOW_URL");
        setParameter("passwordOtpUrl", ParamType.String, this, options, "OAUTH_PASSWORD_OTP_URL");
        setParameter("passwordOobUrl", ParamType.String, this, options, "OAUTH_PASSWORD_OOB_URL");
        setParameter("passwordFlowPage", ParamType.String, this, options, "OAUTH_PASSWORD_FLOW_PAGE");
        setParameter("deviceCodeFlowPage", ParamType.String, this, options, "OAUTH_DEVICECODE_FLOW_PAGE");
        setParameter("deleteTokensPage", ParamType.String, this, options, "OAUTH_DELETE_TOKENS_PAGE");
        setParameter("deleteTokensGetUrl", ParamType.String, this, options, "OAUTH_DELETE_TOKENS_GET_URL");
        setParameter("deleteTokensPostUrl", ParamType.String, this, options, "OAUTH_DELETE_TOKENS_POST_URL");
        setParameter("apiDeleteTokensPostUrl", ParamType.String, this, options, "OAUTHAPI__DELETE_TOKENS_POST_URL");
        setParameter("mfaOtpPage", ParamType.String, this, options, "OAUTH_MFA_OTP_PAGE");
        setParameter("mfaOobPage", ParamType.String, this, options, "OAUTH_MFA_OOB_PAGE");
        setParameter("deviceCodeFlowUrl", ParamType.String, this, options, "OAUTH_DEVICECODE_FLOW_URL");
        setParameter("deviceCodePollUrl", ParamType.String, this, options, "OAUTH_DEVICECODE_POLL_URL");
        setParameter("bffEndpointName", ParamType.String, this, options, "OAUTH_BFF_ENDPOINT_NAME");
        setParameter("bffBaseUrl", ParamType.String, this, options, "OAUTH_BFF_BASEURL");
        setParameter("validFlows", ParamType.JsonArray, this, options, "OAUTH_VALIDFLOWS");
        setParameter("jwtTokens", ParamType.JsonArray, this, options, "OAUTH_JWT_TOKENS");

        if (this.deleteTokensGetUrl?.startsWith("/")) this.deleteTokensGetUrl = this.deleteTokensGetUrl.substring(1);
        if (this.deleteTokensPostUrl?.startsWith("/")) this.deleteTokensPostUrl = this.deleteTokensPostUrl.substring(1);
        if (this.deleteTokensPostUrl?.startsWith("/")) this.deleteTokensPostUrl = this.deleteTokensPostUrl.substring(1);

        if (this.validFlows.length == 1 && this.validFlows[0] == OAuthFlows.All) {
            this.validFlows = OAuthFlows.allFlows();
        } else {
            if (!OAuthFlows.areAllValidFlows(this.validFlows)) {
                throw new CrossauthError(ErrorCode.Configuration, "Invalid flows specificied in " + this.validFlows.join(","));
            }
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
            this.receiveTokenFn = saveInSessionAndLoad;
        } else if (this.tokenResponseType == "saveInSessionAndRedirect") {
            this.receiveTokenFn = saveInSessionAndRedirect;
        }

        if (this.errorResponseType == "custom" && !options.errorFn) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Error response type of custom selected but errorFn not defined");
        }
        if (this.errorResponseType == "custom" && options.errorFn) {
            this.errorFn = options.errorFn;
        } else if (this.errorResponseType == "jsonError") {
            this.errorFn = jsonError;
        } else if (this.errorResponseType == "pageError") {
            this.errorFn = pageError;
        }

        
        if (this,this.loginProtectedFlows.length > 0 && this.loginUrl == "") {
            throw new CrossauthError(ErrorCode.Configuration, 
                "loginUrl must be set if protecting oauth endpoints");
        }
        
        if (!this.prefix.endsWith("/")) this.prefix += "/";
        this.redirect_uri = this.siteUrl + this.prefix + "authzcode";

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode)) {
            this.server.app.get(this.prefix+'authzcodeflow', 
                async (request : FastifyRequest<{ Querystring: ClientAuthorizeQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcodeflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }          
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(request.query.scope);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, request, reply, ce)
                }
                    CrossauthLogger.logger.debug(j({
                        msg: `Authorization code flow: redirecting`,
                        url: url
                    }));
                return reply.redirect(url);
            });
        }

        ///////// Pre Handler

        server.app.addHook('preHandler', async (request : FastifyRequest, _reply : FastifyReply) => {
                
            if (request.user) return;
            if (!server.sessionAdapter) return;

            let sessionData = await server.sessionAdapter.getSessionData(request, this.sessionDataName);
            if (sessionData && sessionData["id_payload"]) {
                let expiry = sessionData["expires_at"]
                if (expiry && expiry > Date.now() && sessionData["id_payload"].sub) {
                    request.user = {
                        id : sessionData["id_payload"].userid ?? sessionData["id_payload"].sub,
                        username : sessionData["id_payload"].sub,
                        state : sessionData["id_payload"].state ?? "active",
                    }
                    request.idTokenPayload = sessionData["id_payload"]
                    request.authType = "oidc";
                }
            }

            if (this.testMiddleware) this.requestObj = request;
        });

        ///////// Authorization code flow with PKCE

        if (this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
            this.server.app.get(this.prefix+'authzcodeflowpkce', 
                async (request : FastifyRequest<{ Querystring: ClientAuthorizeQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcodeflowpkce',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const {url, error, error_description} = 
                    await this.startAuthorizationCodeFlow(request.query.scope, 
                        true);
                if (error || !url) {
                    const ce = CrossauthError.fromOAuthError(error??"server_error", 
                        error_description);
                    return await this.errorFn(this.server, request, reply, ce);
                }
                return reply.redirect(url);
            });
        }

        ///////// Authorization code flow

        if (this.validFlows.includes(OAuthFlows.AuthorizationCode) || 
            this.validFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) ||
            this.validFlows.includes(OAuthFlows.OidcAuthorizationCode)) {
                this.server.app.get(this.prefix+'authzcode', 
                    async (request : FastifyRequest<{ Querystring: RedirectUriQueryType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + 'authzcode',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user &&
                     (this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCodeWithPKCE) || 
                        this.loginProtectedFlows.includes(OAuthFlows.AuthorizationCode))) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }               
                const resp = 
                    await this.redirectEndpoint(request.query.code,
                        request.query.state,
                        request.query.error,
                        request.query.error_description);
                if (resp.id_token) {
                    let payload = this.validateIdToken(resp.id_token);
                    if (!payload) {
                        resp.error = "access_denied";
                        resp.error_description = "Invalid ID token received";
                    }
                }
                try {
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(resp, this, request, reply);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });
        }

        ///////// Client credentials flow

        if (this.validFlows.includes(OAuthFlows.ClientCredentials)) {
            this.server.app.post(this.prefix+'clientcredflow', 
                async (request : FastifyRequest<{ Body: ClientCredentialsBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'clientcredflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (this.server.sessionAdapter) {
                    // if sessions are enabled, require a csrf token
                    const {error, reply: reply1} = 
                        await server.errorIfCsrfInvalid(request,
                            reply,
                            this.errorFn);
                    if (error) return reply1;
                }
                if (!request.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.ClientCredentials))) {
                    return reply.status(401).header(...JSONHDR)
                        .send({ok: false, msg: "Access denied"});                }               
                try {
                    const resp = await this.clientCredentialsFlow(request.body?.scope);
                    if (resp.id_token) {
                        let payload = this.validateIdToken(resp.id_token);
                        if (!payload) {
                            resp.error = "access_denied";
                            resp.error_description = "Invalid ID token received";
                        }
                    }
                    if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(resp, this, request, reply);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });
        }

        ///////// Refresh token flow

        if (this.validFlows.includes(OAuthFlows.RefreshToken)) {
            this.server.app.post(this.prefix+'refreshtokenflow', 
                async (request : FastifyRequest<{ Body: RefreshTokenBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + 'refreshtokenflow',
                        ip: request.ip,
                        user: request.user?.username
                    }));

                // if sessions are enabled, require a csrf token
                const {error, reply: reply1} = 
                    await server.errorIfCsrfInvalid(request,
                        reply,
                        this.errorFn);
                if (error) return reply1;

                // get refresh token from body if present, otherwise
                // try to find in session
                let refreshToken : string | undefined = request.body.refreshToken;
                if (!refreshToken && this.server.sessionAdapter) {

                    if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
                        "Cannot get session data if sessions not enabled");
                    const oauthData =  await this.server.sessionAdapter.getSessionData(request, this.sessionDataName);
        
                    if (!oauthData?.refresh_token) {
                        const ce = new CrossauthError(ErrorCode.BadRequest,
                            "No refresh token in session or in parameters");
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    refreshToken = oauthData.refresh_token;
                } 
                if (!refreshToken) {
                    // TODO: refresh token cookie - call with no refresh token?
                    const ce = new CrossauthError(ErrorCode.BadRequest,
                        "No refresh token supplied");
                    return await this.errorFn(this.server,
                        request,
                        reply,
                        ce);
                }

                if (!request.user && 
                    (this.loginProtectedFlows.includes(OAuthFlows.RefreshToken))) {
                    return reply.status(401).header(...JSONHDR)
                        .send({ok: false, msg: "Access denied"});                }               
                try {
                    const resp = 
                        await this.refreshTokenFlow(refreshToken);
                        if (resp.id_token) {
                            let payload = this.validateIdToken(resp.id_token);
                            if (!payload) {
                                resp.error = "access_denied";
                                resp.error_description = "Invalid ID token received";
                            }
                        }
                        if (resp.error) {
                        const ce = CrossauthError.fromOAuthError(resp.error, 
                            resp.error_description);
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return await this.receiveTokenFn(resp, this, request, reply);
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.error(j({
                        msg: "Error receiving token",
                        cerr: ce,
                        user: request.user?.user
                    }));
                    CrossauthLogger.logger.debug(j({err: e}));
                    return await this.errorFn(this.server, request, reply, ce);
                }
            });

            this.server.app.post(this.prefix+"refreshtokensifexpired", 
                async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "refreshtokensifexpired",
                        ip: request.ip,
                        user: request.user?.username
                    }));
                    return this.refreshTokens(request, reply, false, true);
            });
            this.server.app.post(this.prefix+"api/refreshtokensifexpired", 
                async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "refreshtokens",
                        ip: request.ip,
                        user: request.user?.username
                    }));
                    return this.refreshTokens(request, reply, true, true);
            });

            this.server.app.post(this.prefix+"refreshtokens", 
                async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "refreshtokens",
                        ip: request.ip,
                        user: request.user?.username
                    }));
                    return this.refreshTokens(request, reply, false, false);
            });
            this.server.app.post(this.prefix+"api/refreshtokens", 
                async (request : FastifyRequest<{Body: CsrfBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "refreshtokens",
                        ip: request.ip,
                        user: request.user?.username
                    }));
                    return this.refreshTokens(request, reply, true, false);
            });
        }

        ///////// Password (and MFA) flow

        if (this.validFlows.includes(OAuthFlows.Password) ||
            this.validFlows.includes(OAuthFlows.PasswordMfa)) {
            this.server.app.get(this.prefix+this.passwordFlowUrl, 
                async (request : FastifyRequest<{ Querystring: PasswordQueryType, 
                                                  Body: PasswordBodyType }>, 
                       reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'GET',
                        url: this.prefix + this.passwordFlowUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.user && 
                    this.loginProtectedFlows.includes(OAuthFlows.Password)) {
                    return reply.redirect(302, 
                        this.loginUrl+"?next="+encodeURIComponent(request.url));
                }
                return reply.view(this.passwordFlowPage, {
                    user: request.user,
                    scope: request.query.scope,
                    csrfToken: request.csrfToken
                });            
            });

            this.server.app.post(this.prefix+this.passwordFlowUrl, 
                async (request : FastifyRequest<{ Body: PasswordBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordFlowUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordPost(false, request, reply);
            });

        }

        if (this.validFlows.includes(OAuthFlows.PasswordMfa)) {
            this.server.app.post(this.prefix+this.passwordOtpUrl, 
                async (request : FastifyRequest<{ Body: PasswordOtpType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordOtpUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordOtp(false, request, reply);
            });

            this.server.app.post(this.prefix+this.passwordOobUrl, 
                async (request : FastifyRequest<{ Body: PasswordOobType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.passwordOobUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.passwordOob(false, request, reply);
            });
        }
 
        ///////// Device code flow

        if (this.validFlows.includes(OAuthFlows.DeviceCode)) {

            this.server.app.post(this.prefix+this.deviceCodeFlowUrl, 
                async (request : FastifyRequest<{ Body: DeviceCodeBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.deviceCodeFlowPage,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.deviceCodePost(false, request, reply);
            });

            this.server.app.post(this.prefix+"api/"+this.deviceCodeFlowUrl, 
                async (request : FastifyRequest<{ Body: DeviceCodeBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + "api/" + this.deviceCodeFlowPage,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.deviceCodePost(true, request, reply);
            });

            this.server.app.post(this.prefix+this.deviceCodePollUrl, 
                async (request : FastifyRequest<{ Body: DeviceCodePollBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.deviceCodePollUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.deviceCodePoll(false, request, reply);
            });

            this.server.app.post(this.prefix+"api/"+this.deviceCodePollUrl, 
                async (request : FastifyRequest<{ Body: DeviceCodePollBodyType }>, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.deviceCodePollUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                return await this.deviceCodePoll(true, request, reply);
            });
        }

        ///////// Delete tokens

        if (this.deleteTokensGetUrl) {

            this.server.app.get(this.prefix+this.deleteTokensGetUrl, 
                async (request : FastifyRequest, 
                    reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: 'GET',
                            url: this.prefix + this.deleteTokensGetUrl,
                            ip: request.ip,
                            user: request.user?.username
                        }));
                        return reply.view(this.deleteTokensPage, 
                        {
                            user: request.user?.username,
                            csrfToken: request.csrfToken,
                        });            
            });
        }

        if (this.deleteTokensPostUrl) {

            this.server.app.post(this.prefix+this.deleteTokensPostUrl, 
                async (request : FastifyRequest, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.deleteTokensPostUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                try {
                    await this.deleteTokens(request);
                    return reply.view(this.deleteTokensPage, 
                        {
                            ok: true,
                            user: request.user?.username,
                            csrfToken: request.csrfToken,
                        });            
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug(j({err: ce}));
                    CrossauthLogger.logger.error(j({msg: "Couldn't delete oauth tokens", cerr: ce}));
                    return reply.view(this.deleteTokensPage, 
                        {
                            ok: false,
                            user: request.user?.username,
                            csrfToken: request.csrfToken,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName,
                        });            
                }
            });
        }

        if (this.apiDeleteTokensPostUrl) {

            this.server.app.post(this.prefix+this.apiDeleteTokensPostUrl, 
                async (request : FastifyRequest, 
                    reply : FastifyReply) =>  {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + this.apiDeleteTokensPostUrl,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                try {
                    await this.deleteTokens(request);
                    return reply.header(...JSONHDR).send('{"ok": true}');
                } catch (e) {
                    const ce = CrossauthError.asCrossauthError(e);
                    CrossauthLogger.logger.debug(j({err: ce}));
                    CrossauthLogger.logger.error(j({msg: "Couldn't delete oauth tokens", cerr: ce}));
                    return reply.header(...JSONHDR).status(ce.httpStatus)
                        .send(JSON.stringify({
                            ok: false,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName,
                            csrfToken: request.csrfToken
                        }));            
                }
            });
        }

        ///////// Token endpoints

        for (let tokenType of this.tokenEndpoints) {
            this.server.app.post(this.prefix+tokenType, 
                async (request : FastifyRequest<{Body: TokensBodyType}>, reply : FastifyReply) => {
                    CrossauthLogger.logger.info(j({
                        msg: "Page visit",
                        method: 'POST',
                        url: this.prefix + tokenType,
                        ip: request.ip,
                        user: request.user?.username
                    }));
                if (!request.csrfToken) {
                    return reply.header(...JSONHDR).status(401).send({ok: false, msg: "No csrf token given"});
                }
                let isHave = false;
                let tokenName : string = tokenType;
                if (tokenType.startsWith("have_")) {
                    tokenName = tokenType.replace("have_", "");
                    isHave = true;
                }

                let tokenName1 = tokenName.replace("_token", "")
                let decodeToken = false
                if (this.jwtTokens.includes(tokenName1)) { 
                    decodeToken = request.body.decode ?? true
                }

                if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
                    "Cannot get session data if sessions not enabled");
                const oauthData =  await this.server.sessionAdapter.getSessionData(request, this.sessionDataName);
                if (!oauthData) {
                    if (isHave) return reply.header(...JSONHDR).status(200).send({ok: false});
                    return reply.header(...JSONHDR).status(204).send();
                }
                let payload = oauthData[tokenName];
                //if (["access_token", "id_token"].includes(tokenName)) {
                if (decodeToken)
                    payload = decodePayload(oauthData[tokenName]);
                /*} 
                else if (tokenName == "refresh_token") {
                    payload = {token: payload}
                }*/
                if (!payload) {
                    if (isHave) return reply.header(...JSONHDR).status(200).send({ok: false});
                    return reply.header(...JSONHDR).status(204).send();
                }

                if (isHave) return reply.header(...JSONHDR).status(200).send({ok: true});
                return reply.header(...JSONHDR).status(200).send({...payload});
            });
        }

        this.server.app.post(this.prefix+"tokens", 
            async (request : FastifyRequest<{Body: TokensBodyType}>, reply : FastifyReply) => {
                CrossauthLogger.logger.info(j({
                    msg: "Page visit",
                    method: 'POST',
                    url: this.prefix + "tokens",
                    ip: request.ip,
                    user: request.user?.username
                }));
            if (!request.csrfToken) {
                return reply.header(...JSONHDR).status(401).send({ok: false, msg: "No csrf token given"});
            }
            if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
                "Cannot get session data if sessions not enabled");
            const oauthData =  await this.server.sessionAdapter.getSessionData(request, this.sessionDataName);
            if (!oauthData) {
                return reply.header(...JSONHDR).status(204).send();
            }
            let tokensReturning : {
                access_token?: {[key:string]:any},
                refresh_token?: {[key:string]:any},
                id_token?: {[key:string]:any},
                have_access_token?: boolean,
                have_refresh_token?: boolean,
                have_id_token?: boolean,
            } = {};
            for (let tokenType of this.tokenEndpoints) {
                let isHave = false;
                let tokenName : string = tokenType;
                if (tokenType.startsWith("have_")) {
                    tokenName = tokenType.replace("have_", "");
                    isHave = true;
                }
                let tokenName1 = tokenName.replace("_token", "")
                let decodeToken = false
                if (this.jwtTokens.includes(tokenName1)) { 
                    decodeToken = request.body.decode ?? true
                }
                if (tokenName in oauthData) {
                    let payload = oauthData[tokenName];
                    if (decodeToken)
                        payload = decodePayload(oauthData[tokenName]);
                    if (payload) {
                        // @ts-ignore it doesn't recognize we filtered out _have
                        tokensReturning[tokenType] = isHave ? true : payload;
                    }    
                } else if (isHave) {
                    // @ts-ignore it doesn't recognize we filtered on _have
                    tokensReturning[tokenType] = false;
                }
    
            }

            return reply.header(...JSONHDR).status(200).send({...tokensReturning});
        });

        // Add BFF endpoints
        if (this.bffEndpoints.length > 0 && !this.bffBaseUrl) {
            throw new CrossauthError(ErrorCode.Configuration, "If enabling BFF endpoints, must also define bffBaseUrl");
        }
        if (this.bffBaseUrl == undefined) this.bffBaseUrl = ""; // to stop vs code errors
        if (this.bffBaseUrl.endsWith("/")) this.bffBaseUrl = this.bffBaseUrl.substring(0, this.bffBaseUrl.length-1);
        for (let i=0; i<this.bffEndpoints.length; ++i) {
            const url = this.bffEndpoints[i].url;
            if (url.includes("?") || url.includes("#")) {
                throw new CrossauthError(ErrorCode.Configuration, "BFF urls may not contain query parameters or page fragments");
            }
            if (!(url.startsWith("/"))) {
                throw new CrossauthError(ErrorCode.Configuration, "BFF urls must be absolute and without the HTTP method, hostname or port");

            }
            const methods = this.bffEndpoints[i].methods;
            const matchSubUrls = this.bffEndpoints[i].matchSubUrls??false;
            let route = url;
            if (matchSubUrls) {
                if (!(route.endsWith("/"))) route += "/";
                route += "*";
            }
            for (let i in methods) {
                this.server.app.route({
                    method: methods[i],
                    url: this.prefix + this.bffEndpointName + url,
                    handler: async (request : FastifyRequest<{Body: CsrfBodyType}>, 
                        reply : FastifyReply) =>  {
                        CrossauthLogger.logger.info(j({
                            msg: "Page visit",
                            method: request.method,
                            url: request.url,
                            ip: request.ip,
                            user: request.user?.username
                        }));
                        const url = request.url.substring(this.prefix.length +
                            this.bffEndpointName.length);
                        CrossauthLogger.logger.debug(j({msg: "Resource server URL " + url}))
                        const csrfRequired = 
                            (methods[i] != "GET" && methods[i] != "HEAD" && methods[i] != "OPTIONS");
                        if (this.server.sessionAdapter && csrfRequired) {
                            // if sessions are enabled, require a csrf token
                            const {error, reply: reply1} =
                                await server.errorIfCsrfInvalid(request,
                                    reply,
                                    this.errorFn);
                            if (error) return reply1;
                        }
                
                        try {
                            if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
                                    "Cannot get session data if sessions not enabled");
                            const oauthData =  await this.server.sessionAdapter.getSessionData(request, this.sessionDataName);
                            if (!oauthData) {
                                return reply.header(...JSONHDR).status(401)
                                    .send({ok: false});
                            }
                            let access_token = oauthData?.access_token;
                            if (oauthData && oauthData.access_token) {
                                const resp = 
                                    await server.oAuthClient?.refresh(request,
                                        reply,
                                        true,
                                        true,
                                        oauthData.refresh_token,
                                        oauthData.expires_at);
                                if (resp?.access_token) {
                                    access_token = resp.access_token;
                                }
                            }
                            let headers : {[key:string]: string} = {
                                    'Accept': 'application/json',
                                    'Content-Type': 'application/json',
                            }
                            if (access_token) headers["Authorization"] 
                                = "Bearer " + access_token;
                            let resp : Response;
                            if (request.body) {
                                resp = await fetch(this.bffBaseUrl + url, {
                                    headers:headers,
                                    method: request.method,
                                    body: JSON.stringify(request.body??"{}"),
                                });    
                            } else {
                                resp = await fetch(this.bffBaseUrl + url, {
                                    headers:headers,
                                    method: request.method,
                                });    
                            }
                            const body = await resp.json();
                            for (const pair of resp.headers.entries()) {
                                reply = reply.header(pair[0], pair[1]);
                            }
                            return reply.header(...JSONHDR).status(resp.status)
                                .send(body);
                        } catch (e) {
                            CrossauthLogger.logger.error(j({err: e}));
                            return reply.header(...JSONHDR).status(500).send({});
        
                        }
                    }
    
                });
            }
        }
    }

    private async passwordPost(isApi: boolean,
        request: FastifyRequest<{ Body: PasswordBodyType }>,
        reply: FastifyReply) {
        if (this.server.sessionAdapter) {
            // if sessions are enabled, require a csrf token
            const {error, reply: reply1} = 
                await this.server.errorIfCsrfInvalid(request,
                    reply,
                    this.errorFn);
            if (error) return reply1;
        }
        try {
            let resp = 
                await this.passwordFlow(request.body.username,
                    request.body.password,
                    request.body.scope);
            if (resp.id_token) {
                let payload = this.validateIdToken(resp.id_token);
                if (!payload) {
                    resp.error = "access_denied";
                    resp.error_description = "Invalid ID token received";
                }
            }
            if (resp.error == "mfa_required" && 
                resp.mfa_token &&
                this.validFlows.includes(OAuthFlows.PasswordMfa)) {
                const mfa_token = resp.mfa_token;
                resp = await this.passwordMfa(isApi,
                    mfa_token,
                    request.body.scope,
                    request,
                    reply);
                if (resp.id_token) {
                    let payload = this.validateIdToken(resp.id_token);
                    if (!payload) {
                        resp.error = "access_denied";
                        resp.error_description = "Invalid ID token received";
                    }
                }
                if (resp.error) {
                    const ce = CrossauthError.fromOAuthError(resp.error, 
                        resp.error_description);
                    if (isApi)  {
                        return await this.errorFn(this.server,
                            request,
                            reply,
                            ce);
                    }
                    return reply.view(this.passwordFlowPage, 
                        {
                            user: request.user,
                            username: request.body.username,
                            password: request.body.password,
                            scope: request.body.scope,
                            errorMessage: ce.message,
                            errorCode: ce.code,
                            errorCodeName: ce.codeName,
                            csrfToken: request.csrfToken
                        });            
                }
                return await this.receiveTokenFn(resp, this, request, reply);
               
            } else if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, 
                    resp.error_description);
                if (isApi)  {
                    return await this.errorFn(this.server, request,reply, ce);
                }
                return reply.view(this.passwordFlowPage, 
                    {
                        user: request.user,
                        username: request.body.username,
                        //password: request.body.password,
                        scope: request.body.scope,
                        errorMessage: ce.message,
                        errorCode: ce.code,
                        errorCodeName: ce.codeName,
                        csrfToken: request.csrfToken
                    });            
            }
            return await this.receiveTokenFn(resp, this, request, reply);
        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: request.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.passwordFlowPage, {
                user: request.user,
                username: request.body.username,
                password: request.body.password,
                scope: request.body.scope,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
    }

    private async passwordMfa(
        _isApi : boolean,
        mfa_token: string,
        scope : string|undefined,
        _request: FastifyRequest,
        _reply: FastifyReply
    ) : Promise<MfaAuthenticatorsResponse|OAuthTokenResponse> {

        const authenticatorsResponse = 
            await this.mfaAuthenticators(mfa_token);
        if (authenticatorsResponse.error || 
            !authenticatorsResponse.authenticators ||
            !Array.isArray(authenticatorsResponse.authenticators) ||
            authenticatorsResponse.authenticators.length == 0 ||
            (authenticatorsResponse.authenticators.length > 1 && 
                !authenticatorsResponse.authenticators[0].active )) {
                    if (authenticatorsResponse.error) {
                        return authenticatorsResponse
                    } else {
                        return {
                            error: "access_denied",
                            error_description: "No MFA authenticators available"
                    };
        
                }
        }

        const auth = authenticatorsResponse.authenticators[0] as MfaAuthenticatorResponse;
        if (auth.authenticator_type == "otp") {
            const resp = await this.mfaOtpRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="otp") {
                return {
                    error: resp.error??"server_error",
                    error_description: resp.error_description??"Invalid response from MFA OTP challenge"
                }
            }
            return  {
                scope: scope,
                mfa_token: mfa_token,
            };            
        } else if (auth.authenticator_type == "oob") {
            const resp = await this.mfaOobRequest(mfa_token, auth.id);
            if (resp.error || resp.challenge_type!="oob" || !resp.oob_code || 
                resp.binding_method != "prompt") {
                return {
                    error: resp.error??"server_error",
                    error_description: resp.error_description??"Invalid response from MFA OOB challenge"
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
            error_description: ce.message
        }
    }

    private async passwordOtp(isApi: boolean,
        request: FastifyRequest<{Body : PasswordOtpType}>,
        reply: FastifyReply
    ) : Promise<FastifyReply> {

        const resp = await this.mfaOtpComplete(request.body.mfa_token, 
            request.body.otp);
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                cerr: ce,
                user: request.user?.user,
                hashedMfaToken: Crypto.hash(request.body.mfa_token),
            }));
            CrossauthLogger.logger.debug(j({err: ce}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.mfaOtpPage, {
                user: request.user,
                scope: request.body.scope,
                mfa_token: request.body.mfa_token,
                challenge_tpye: request.body.challenge_type,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
        return await this.receiveTokenFn(resp, this, request, reply)??reply;
    }

    private async passwordOob(isApi: boolean,
        request: FastifyRequest<{Body : PasswordOobType}>,
        reply: FastifyReply
    ) : Promise<FastifyReply> {

        const resp = await this.mfaOobComplete(request.body.mfa_token, 
            request.body.oob_code,
            request.body.binding_code);
        if (resp.id_token) {
            let payload = this.validateIdToken(resp.id_token);
            if (!payload) {
                resp.error = "access_denied";
                resp.error_description = "Invalid ID token received";
            }
        }
        if (resp.error) {
            const ce = CrossauthError.fromOAuthError(resp.error,
                resp.error_description??"Error completing MFA");
            CrossauthLogger.logger.warn(j({
                msg: "Error completing MFA",
                cerr: ce,
                user: request.user?.user,
                hashedMfaToken: Crypto.hash(request.body.mfa_token),
            }));
            CrossauthLogger.logger.debug(j({err: ce}));
            if (isApi) return await this.errorFn(this.server,
                request,
                reply,
                ce);
            return reply.view(this.mfaOobPage, {
                user: request.user,
                scope: request.body.scope,
                oob_code: request.body.mfa_token,
                name: request.body.name,
                challenge_tpye: request.body.challenge_type,
                mfa_token: request.body.mfa_token,
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
                csrfToken: request.csrfToken
            });
        }
        return await this.receiveTokenFn(resp, this, request, reply)??reply;
    }

    private async deviceCodePost(isApi: boolean,
        request: FastifyRequest<{ Body: DeviceCodeBodyType }>,
        reply: FastifyReply) {
        if (this.server.sessionAdapter) {
            // if sessions are enabled, require a csrf token
            const {error, reply: reply1} = 
                await this.server.errorIfCsrfInvalid(request,
                    reply,
                    this.errorFn);
            if (error) return reply1;
        }
        try {
            if (!request.csrfToken) {
                throw new CrossauthError(ErrorCode.Unauthorized, "CSRF token missing or invalid");
            }

            let url = this.authServerBaseUrl;
            if (!(url.endsWith("/"))) url += "/";
            url += this.deviceAuthorizationUrl;
            const resp =  await this.startDeviceCodeFlow(url, request.body.scope);

            if (resp.error) {
                const ce = CrossauthError.fromOAuthError(resp.error, resp.error_description);
                const data = {
                    user: request.user,
                    scope: request.body.scope,
                    errorMessage: ce.message,
                    errorCode: ce.code,
                    errorCodeName: ce.codeName,
                    csrfToken: request.csrfToken,
                    error: resp.error,
                    error_description: resp.error_description,
                };
                if (isApi) {
                    return reply.header(...JSONHDR).status(ce.httpStatus).send(resp);
                } else {
                    return reply.view(this.deviceCodeFlowPage, data);            

                }
            }

            let qrUrl : string|undefined = undefined;
            if (resp.verification_uri_complete) {
                await QRCode.toDataURL(resp.verification_uri_complete)
                    .then((url) => {
                            qrUrl = url;
                    })
                    .catch((err) => {
                        CrossauthLogger.logger.debug(j({err: err}));
                        CrossauthLogger.logger.warn(j({msg: "Couldn't generate verification URL QR Code"}))
                    });
        
            }

            if (isApi) {
                return reply.header(...JSONHDR).send(resp);
            } else {
                return reply.view(this.deviceCodeFlowPage, 
                    {
                        user: request.user,
                        scope: request.body.scope,
                        verification_uri_qrdata: qrUrl,
                        ...resp
                    });            
            }

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: request.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            const data = {
                errorMessage: ce.message,
                errorCode: ce.code,
                errorCodeName: ce.codeName,
            };
            if (isApi) return reply.header(...JSONHDR).status(ce.httpStatus).send(data);

            return reply.view(this.deviceCodeFlowPage, {
                user: request.user,
                csrfToken: request.csrfToken,
                scope: request.body.scope,
                ...data,
            });
        }
    }

    private async deviceCodePoll(isApi : boolean, request: FastifyRequest<{ Body: DeviceCodePollBodyType }>,
        reply: FastifyReply) {
        // CSRF protection is disabled because this just wraps the OAuth token
        // endpoint, which does nothing with cookies
        /*if (this.server.sessionAdapter) {
            // if sessions are enabled, require a csrf token
            const {error, reply: reply1} = 
                await this.server.errorIfCsrfInvalid(request,
                    reply,
                    this.errorFn);
            if (error) return reply1;
        }*/
        try {

            const resp =  await this.pollDeviceCodeFlow(request.body.device_code);
            if (resp.id_token) {
                let payload = this.validateIdToken(resp.id_token);
                if (!payload) {
                    resp.error = "access_denied";
                    resp.error_description = "Invalid ID token received";
                }
            }

            if (resp.error) {
                return reply.header(...JSONHDR)
                .send(resp);

            }

            return await this.receiveTokenFn(resp,
                this,
                request,
                isApi ? undefined : reply);

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.error(j({
                msg: "Error receiving token",
                cerr: ce,
                user: request.user?.user
            }));
            CrossauthLogger.logger.debug(j({err: e}));
            return await this.errorFn(this.server,
                request,
                reply,
                ce);
        }
    }

    async refresh(request: FastifyRequest,
        reply : FastifyReply,
        silent : boolean,
        onlyIfExpired : boolean,
        refreshToken?: string,
        expiresAt?: number) 
        : Promise<{
            refresh_token?: string,
            access_token?: string,
            expires_in?: number,
            expires_at?: number,
            error?: string,
            error_description?: string,
            id_token? : string
        }|FastifyReply|undefined> {
            if (!expiresAt || !refreshToken) {
                if (!silent) {
                    return await this.receiveTokenFn({},
                        this,
                        request,
                        silent ? undefined : reply);
                }
                return undefined;
            }

        if (!onlyIfExpired || expiresAt <= Date.now()) {
            try {
                const resp = await this.refreshTokenFlow(refreshToken);
                if (resp.id_token) {
                    let payload = this.validateIdToken(resp.id_token);
                    if (!payload) {
                        resp.error = "access_denied";
                        resp.error_description = "Invalid ID token received";
                    }
                }
                if (!resp.error && !resp.access_token) {
                    resp.error = "server_error";
                    resp.error_description = "Unexpectedly did not receive error or access token";
                }
                if (!resp.error) {
                    const resp1 = await this.receiveTokenFn(resp,
                        this,
                        request,
                        silent ? undefined : reply);
                    if (!silent) return resp1;
                } 
                if (!silent) {
                    const ce = CrossauthError.fromOAuthError(resp.error??"server_error", 
                        resp.error_description);
                    return await this.errorFn(this.server, request, reply, ce)
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
                    return await this.errorFn(this.server, request, reply, ce)
                }
                return {
                    error: "server_error",
                    error_description: "Failed refreshing access token"
                };
            }
        }
        return undefined;
    }

    private async refreshTokens(request: FastifyRequest<{ Body: CsrfBodyType }>,
        reply: FastifyReply,
        silent: boolean,
        onlyIfExpired : boolean) {
        if (!request.csrfToken) {
            return reply.header(...JSONHDR).status(401).send({ok: false, msg: "No csrf token given"});
        }
        if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot get session data if sessions not enabled");
        const oauthData =  await this.server.sessionAdapter.getSessionData(request, this.sessionDataName);
        if (!oauthData?.refresh_token) {
            if (silent) {
                return reply.header(...JSONHDR).status(204).send();
            } else {
                const ce = new CrossauthError(ErrorCode.InvalidSession,
                    "No tokens found in session")
                return await this.errorFn(this.server,
                    request,
                    reply,
                    ce);
            }
        }

        const resp = 
            await this.refresh(request,
                reply,
                silent,
                onlyIfExpired,
                oauthData.refresh_token,
                //onlyIfExpired ? oauthData.expires_at : undefined
                oauthData.expires_at
            );
        if (resp && resp.id_token) {
            let payload = this.validateIdToken(resp.id_token);
            if (!payload) {
                resp.error = "access_denied";
                resp.error_description = "Invalid ID token received";
            }
        }
        if (!silent) {
            if (resp == undefined) return this.receiveTokenFn({}, this, request, reply);
            if (resp != undefined) return resp; 
        }
        return reply.header(...JSONHDR).status(200).send({ok: true, expires_at: resp?.expires_at});
    }

    private async deleteTokens(request: FastifyRequest) : Promise<void> {
        if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot delete tokens if sessions not enabled");
        if (!request.csrfToken) {
            throw new CrossauthError(ErrorCode.InvalidSession,
                "Missing or incorrec CSRF token")
        }

        if (!this.server.sessionAdapter) throw new CrossauthError(ErrorCode.Configuration, 
            "Cannot delete session data if sessions not enabled");
        await this.server.sessionAdapter.deleteSessionData(request, this.sessionDataName);
    }    
}
