/**
 * A key (eg session ID, email reset token) as stored in a database table.
 * 
 * The fields defined here are the ones used by Crossauth.  You may add
 * others.
 */
export interface Key {

    /** The value of the keykey.
     * 
     * In a cookie, the value part of cookiename=value; options... 
     */
    value : string,

    /** The date/time the key was created, in local time on the server */
    created : Date,

    /** The date/time the key expires */
    expires : Date | undefined,

    /** the user this key is for (or undefined for an anonymous session ID)
     * 
     * It accepts the value null as usually this is the value stored in the
     * database, rather than undefined.  Some functions need to differentiate
     * between a null value as opposed to the value not being defined (eg for
     * a partial update).
     */
    userId : string | number | undefined | null,

    /** The date/time key was last used (eg last time a request was made
     * with this value as a session ID)
     */
    lastActive? : Date,

    /** Additional key-specific data (eg new email address for email change).
     * 
     * While application specific, any data Crossauth puts in this field
     * is a stringified JSON, with its own key so it can co-exist with
     * other data.
     */
    data? : string,

    /** This allows users to add additional fields, which if present in the
     * database will be loaded into this object.
     */
    [ key : string ] : any,

}

/**
 * An API key is a string that can be used in place of a username and 
 * password.  These are not automatically created, like OAuth access tokens.
 */
export interface ApiKey extends Key {

    /** A name for the key, unique to the user */
    name : string,
}

/**
 * Given a key object, parses JSON data in the `data` field anmd returns
 * it as an object
 * @param key the key object containing the data to parse in `data`.
 * @returns an object with the parsed JSON data.
 */
export function getJsonData(key : Key) : {[key:string]:any} {
    if (!key.data) return {}
    try {
        return JSON.parse(key.data);
    } catch {
        return {};
    }
}

/**
 * Describes a user as fetched from the user storage (eg, database table),
 * excluding auto-generated fields such as an auto-generated ID
 * 
 * This is extendible with additional fields - provide them to the 
 * {@link @crossauth/backend!UserStorage} class as `extraFields`.
 * 
 * You may want to do this if you want to pass additional user data back to the 
 * caller, eg real name.
 * 
 * The fields defined here are the ones used by Crossauth.  You may add
 * others.
 */
export interface UserInputFields {

    /** The username.  This may be an email address or anything else,
     * application-specific.
     */
    username : string,

    /**
     * You are free to define your own states.  The ones Crossauth recognises
     * are defined in {@link UserState}.
     */
    state : string,

    /**
     * You can optionally include an email address field in your user table.
     * If your username is an email address, you do not need a separate field.
     */
    email? : string,

    /**
     * Whether or not the user has administrator priviledges (and can acess
     * admin-only functions).
     */
    admin? : boolean,

    /**
     * This is included as any other fields in your user table will 
     * automatically be added to the user object if they are included in 
     * `extraFields` in {@link @crossauth/backend!UserStorage}.
     */
    [ key : string ] : any,
}

/**
 * This adds ID to {@link UserInputFields}.  
 * 
 * If your `username` field is
 * unique and immutable, you can omit ID (passing username anywhere an ID)
 * is expected.  However, if you want users to be able to change their username,
 * you should include ID field and make that immutable instead.
 */
export interface User extends UserInputFields {

    /** ID fied, which may be auto-generated */
    id : string | number,
}

/**
 * Secrets, such as a password, are not in the User object to prevent them
 * accidentally being leaked to the frontend.  All functions that return
 * secrets return them in this separate object.
 * 
 * The fields in this class are the ones that are not autogenerated by the
 * database.
 */
export interface UserSecretsInputFields {
    password? : string,
    totpSecret? : string,
    otp?: string,
    expiry?: number,
    [key:string] : any,
}

/**
 * This adds the user ID toi {@link UserSecretsInputFields}.
 */
export interface UserSecrets extends UserSecretsInputFields {
    userId : string|number,
}

/** OAuth client data as stored in a database table */
export interface OAuthClient {

    /** The clientId, which is auto-generated and immutable */
    clientId : string,

    /** Whether or not the client is confidential (and can therefore
     * keep the client secret secret) */
    confidential : boolean,

    /**
     * A user-friendly name for the client (not used as part of the OAuth
     * API).
     */
    clientName : string,

    /**
     * Client secret, which is autogenerated.  
     * 
     * If there is no client secret, it should be set to `undefined`.
     * 
     * This field allows `null` as well as `undefined` this is used, for 
     * example, when partially updating a client and you specifically 
     * want to set the secret to undefined, as opposed to just not wishing
     * to change the value.  Other than that, this value is always either
     * a string or `undefined`.
     */
    clientSecret? : string|null,

    /**
     * An array of value redirect URIs for the client.
     */
    redirectUri : string[],

    /**
     * An array of OAuth flows allowed for this client.  
     * 
     * See {@link @crossauth/common!OAuthFlows}.
     */
    validFlow : string[],


    /**
     * ID of the user who owns this client, which may be `undefined`
     * for not being owned by a specific user.  
     * 
     * This field allows `null` as well as `undefined` this is used, for 
     * example, when partially updating a client and you specifically 
     * want to set the user ID to undefined, as opposed to just not wishing
     * to change the value.  Other than that, this value is always either
     * a string or number (depending on the ID type in your user storage)
     * or `undefined`.
     */
    userId? : string|number|null,
    [ key : string ] : any,
}

/**
 * Although the `state` field in {@link User} can be any string, these
 * are the values recognised and used by Crossauth.
 */
export class UserState {

    /** Ordinary, active user who can log in freely */
    static readonly active = "active";

    /** Deactivated account.  User cannot log in */
    static readonly disabled = "disabled";

    /** Two factor authentication has been actived for this user
     * but has not yet been configured.  Once a user logs in,
     * they will be directed to a page to configure 2FA and will
     * not be able to do anything else (that requires login) until
     * they have done so.
     */
    static readonly awaitingTwoFactorSetup = "awaitingtwofactorsetup";

    /** Email verification has been turned on but user has not
     * verified his or her email address.  Cannot log on until it has
     * been verified.
     */
    static readonly awaitingEmailVerification = "awaitingemailverification";

    /**
     * If the state is set to this, the user may not access any
     * login-required functions unless he or she has changed their password.
     * 
     * Upon login, the user is redirected to the change password page.
     */
    static readonly passwordChangeNeeded = "passwordchangeneeded";

    /**
     * If the state is set to this, the user may not access any
     * login-required functions unless he or she has reset their password.
     * 
     * Upon login, the user is redirected to the reset password page.
     */
    static readonly passwordResetNeeded = "passwordresetneeded";

    /**
     * If the state is set to this, the user may not access any
     * login-required functions unless he or she has reset their second
     * factor configuration.
     * 
     * Upon login, the user is redirected to the 2FA configuration page.
     * 
     * If you create a user and 2FA is mandatory, you can set state to 
     * this value and the user will then be prompted to configure 2FA 
     * upon login.
     */
    static readonly factor2ResetNeeded = "factor2resetneeded";
}

/**
 * You can have one key table for everything or separate key tables for
 * different types of keys.  So that different types of keys can 
 * coexist, their values are prefixed by these strings
 */
export class KeyPrefix {

    /** Session ID */
    static readonly session = "s:"

    /** Password Reset Token */
    static readonly passwordResetToken = "p:"

    /** Email verification token */
    static readonly emailVerificationToken = "e:"

    /** API key */
    static readonly apiKey = "api:"

    /** OAuth authorization code */
    static readonly authorizationCode = "authz:";

    /** OAuth access token */
    static readonly accessToken = "access:";

    /** OAuth refresh token */
    static readonly refreshToken = "refresh:";

    /** OAuth MFA key (used by the password MFA flow) */
    static readonly mfaToken = "omfa:";
}