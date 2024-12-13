// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { CrossauthError, CrossauthLogger, ErrorCode, OAuthClientBase, j } from '@crossauth/common';
import { Crypto } from '../crypto';
import { setParameter, ParamType } from '../utils';
import {
    OAuthTokenConsumer,
    type OAuthTokenConsumerOptions } from './tokenconsumer';
import type { User, UserSecrets } from '@crossauth/common';
import { UserStorage } from '../storage';

/**
 * Options for {@link OAuthClientBackend}
 */
export interface OAuthClientOptions extends OAuthTokenConsumerOptions {

    /** Length of random state variable for passing to `authorize` endpoint
     * (before bsae64-url-encoding)
     */
    stateLength? : number,

    /** Length of random code verifier to generate 
     * (before bsae64-url-encoding) 
     * */
    verifierLength? : number,

    /**
     * Client ID for this client
     */
    client_id? : string,

    /**
     * Client secret for this client (can be undefined for no secret)
     */
    client_secret? : string,

    /**
     * Redirect URI to send in `authorize` requests
     */
    redirect_uri? : string,

    /**
     * Type of code challenge for PKCE
     */
    codeChallengeMethod? : "plain" | "S256",

    /**
     * URL to call for the device_authorization endpoint, relative to
     * the `authServerBaseUrl`.
     * 
     * Default `device_authorization`
     */
    deviceAuthorizationUrl? : string,

    /**
     * If set to true, users must also have a local account to log in
     * with OIDC.
     * Default false
     */
    requireLocalAccount? : boolean

    /**
     * If using the BFF method, you can also create a user in the sesion
     * when the token is received, just like session management 
     * (`event.locals.user` for Sveltekit, `request.user`) for Fastify.
     * 
     * Set this field to `merge` to do this by merging the ID token fields
     * with the User fields.  `embed` will put the ID token fields in `idToken`
     * in the user.  `custom` will call the user-defined function `userCreationFn`.
     * th user will be set to undefined;  If it is set to `idToken` (the default)
     * then a user object is created from the token without first checking
     * for a user in storage.
     * 
     * Matching is done in the fields given in `userMatchField` and
     * `idTokenMatchField`.
     * 
     * Default is `idToken`, which does not require a local account
     */
    userCreationType? : 
        "idToken" |
        "merge" |
        "embed" |
        "custom";
    
    /**
     * Field in user table to to match with idToken when `userCreationType`
     * is set to `merge` or `embed`.  Default `username`.
     */
    userMatchField? : string;

    /**
     * Field in ID token to to match with idToken when `userCreationType`
     * is set to `merge` or `embed`.  Default `sub`.
     */
    idTokenMatchField? : string;

    /**
     * Supply this function if you set `userCreationType` to `custom`.
     * 
     * @param idToken the ID token returned by the authorization server.
     * @param userStorage where to search for the user
     * @param userMatchField the `userMatchField` from options
     * @param idTokenMatchField the `idTokenMatchField` from options
     * @returns A {@link @crossauth/common!User} object or undefined if you
     * want to reject the user.
     */
    userCreationFn?: (idToken: {[key:string]:any}, 
        userStorage: UserStorage|undefined, 
        userMatchField : string, 
        idTokenMatchField : string) => Promise<User|undefined>;

    /**
     * If you set userCreationType to something other than `idToken`,
     * you must also provide the user storage.
     */
    userStorage? : UserStorage;

    /**
     * If set to JSON, make calls to the token endpoint as JSON, otherwise
     * as x-www-form-urlencoded.
     */
    oauthPostType? : "json" | "form";

    /**
     * If true and log level is set to debug, also log fetch requests and
     * results.
     * 
     * Off by default for security reasons.
     */
    oauthLogFetch? : boolean;

}

/**
 * An OAuth clientframework-independent base class)
 * 
 * Most of the functionality is in the base class 
 * {@link @crossauth/common!OAuthClientBase}.  However that class is designed
 * to work in the browser as well as node, and therefore the cryptography
 * is let out of there and added in here.
 */
export class OAuthClientBackend extends OAuthClientBase {

    protected deviceAuthorizationUrl : string = "device_authorization";
    protected userCreationType :  "idToken" |
    "merge" |
    "embed" |
    "custom" = "idToken";
    protected userMatchField : string = "username";
    protected idTokenMatchField : string = "sub";
    protected userCreationFn: (idToken: {[key:string]:any}, 
        userStorage: UserStorage|undefined, 
        userMatchField : string, 
        idTokenMatchField : string) => Promise<User|undefined>;
    protected userStorage? : UserStorage;

    /**
     * Constructor
     * @param authServerBaseUrl bsae URI for the authorization server
     *        expected to issue access tokens.  If the `iss` field in a JWT
     *        does not match this, it is rejected.
     * @param options See {@link OAuthClientOptions}
     */
    constructor(authServerBaseUrl : string, options : OAuthClientOptions) {
        // because we can't set instance variables before calling super()
        const options1 = {
            client_id: "",
        }
        setParameter("client_id", ParamType.String, options1, options, "OAUTH_CLIENT_ID", true);
        super({ authServerBaseUrl, 
            tokenConsumer: new OAuthTokenConsumer(
                options1.client_id, { 
                audience: options1.client_id, 
                authServerBaseUrl, 
                ...options }), ...options });
        this.client_id = options1.client_id;

        let tmp : {[key:string]: any} = {};
        setParameter("stateLength", ParamType.String, this, options, "OAUTH_STATE_LENGTH");
        setParameter("verifierLength", ParamType.String, this, options, "OAUTH_VERIFIER_LENGTH");
        setParameter("client_secret", ParamType.String, tmp, options, "OAUTH_CLIENT_SECRET");
        setParameter("codeChallengeMethod", ParamType.String, this, options, "OAUTH_CODE_CHALLENGE_METHOD");
        setParameter("deviceAuthorizationUrl", ParamType.String, this, options, "OAUTH_DEVICE_AUTHORIZATION_URL");
        setParameter("oauthLogFetch", ParamType.Boolean, this, options, "OAUTH_LOG_FETCH");
        if (this.deviceAuthorizationUrl.startsWith("/")) this.deviceAuthorizationUrl = this.deviceAuthorizationUrl.substring(1);
        if (tmp.client_secret) this.client_secret = tmp.client_secret;

        setParameter("userCreationType", ParamType.String, this, options, "OAUTH_USER_CREATION_TYPE");
        setParameter("userMatchField", ParamType.String, this, options, "OAUTH_USER_MATCH_FIELD");
        setParameter("idTokenMatchField", ParamType.String, this, options, "OAUTH_IDTOKEN_MaTCH_FIELD");
        if (this.userCreationType == "merge") this.userCreationFn = mergeUserCreationFunction;
        else if (this.userCreationType == "embed") this.userCreationFn = embedUserCreationFunction;
        else if (options.userCreationFn && this.userCreationType == "custom") this.userCreationFn = options.userCreationFn;
        else this.userCreationFn = idTokenUserCreationFunction;
        if (options.userStorage) this.userStorage = options.userStorage;
        setParameter("oauthPostType", ParamType.String, this, options, "OAUTH_POST_TYPE");
        setParameter("oauthUseUserInfoEndpoint", ParamType.Boolean, this, options, "OAUTH_USE_USER_INFO_ENDPOINT");
        setParameter("oauthAuthorizeRedirect", ParamType.String, this, options, "OAUTH_AUTHORIZE_REDIRECT");
        if (this.oauthPostType != "json" && this.oauthPostType != "form") {
            throw new CrossauthError(ErrorCode.Configuration, "oauthPostType must be json or form")
        }
    }

    /**
     * Uses {@link @crossauth/backend!Crypto.randomValue} to create a random string
     * @param length the length of the random array of bytes before
     *        base64-url-encoding
     * @returns the Base64-URL-encoded random string
     */
    protected randomValue(length : number) : string {
        return Crypto.randomValue(length);
    }

    /**
     * Uses {@link @crossauth/backend!Crypto.sha256} to create hash a string using SHA256
     * @param plaintext the text to hash
     * @returns the Base64-URL-encoded hash
     */
    protected async sha256(plaintext :string) : Promise<string> {
        return Crypto.sha256(plaintext);
    }
}

export async function mergeUserCreationFunction(idToken : {[key:string]:any}, 
    userStorage: UserStorage|undefined, 
    userMatchField : string, 
    idTokenMatchField : string) : Promise<User|undefined> {

    if (!userStorage) throw new CrossauthError(ErrorCode.Configuration, "userCreationType set to merge but no user storage set")
    try {
        let ret : {user: User, secrets: UserSecrets};
        if (userMatchField == "username") ret = await userStorage.getUserByUsername(idToken[idTokenMatchField]);
        else if (userMatchField == "username") ret = await userStorage.getUserByEmail(idToken[idTokenMatchField]);
        else ret = await userStorage.getUserBy(userMatchField, idToken[idTokenMatchField]);
        return {...idToken, ...ret.user};
    } catch (e) {
        const ce = CrossauthError.asCrossauthError(e);
        if (ce.code == ErrorCode.UserNotExist || ce.code == ErrorCode.UserNotActive) {
            return undefined;
        }
        CrossauthLogger.logger.error(j({err: e}));
        throw e;
    }
}

export async function embedUserCreationFunction(idToken : {[key:string]:any}, 
    userStorage: UserStorage|undefined, 
    userMatchField : string, 
    idTokenMatchField : string) : Promise<User|undefined> {

    if (!userStorage) throw new CrossauthError(ErrorCode.Configuration, "userCreationType set to embed but no user storage set")
    try {
        let ret : {user: User, secrets: UserSecrets};
        if (userMatchField == "username") ret = await userStorage.getUserByUsername(idToken[idTokenMatchField]);
        else if (userMatchField == "username") ret = await userStorage.getUserByEmail(idToken[idTokenMatchField]);
        else ret = await userStorage.getUserBy(userMatchField, idToken[idTokenMatchField]);
        return {...ret.user, idToken};
    } catch (e) {
        const ce = CrossauthError.asCrossauthError(e);
        if (ce.code == ErrorCode.UserNotExist || ce.code == ErrorCode.UserNotActive) {
            return undefined;
        }
        CrossauthLogger.logger.error({err: e});
        throw e;
    }
}

export async function idTokenUserCreationFunction(idToken : {[key:string]:any}, 
    _userStorage: UserStorage|undefined, 
    _userMatchField : string, 
    _idTokenMatchField : string) : Promise<User|undefined> {

    return {
        id : idToken.userid ?? idToken.sub,
        username : idToken.sub,
        state : idToken.state ?? "active",
    }
}
