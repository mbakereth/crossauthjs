/**
 * A key (eg session ID) as stored in a key database table and send to the client as a cookie
 */
export interface Key {

    /** The key - in a cookie, the value part of cookiename=value; options... */
    value : string,

    /** The date/time the key was created, in local time on the server */
    created : Date,

    /** The date/time the key expires */
    expires : Date | undefined,

    /** the user this key is for (or undefined for an anonymous session ID) */
    userId : string | number | undefined | null,

    /** The /time the session was last active */
    lastActive? : Date,

    /** additional key-specific data (eg new email address for email change) */
    data? : string,

    [ key : string ] : any,

}

export interface ApiKey extends Key {

    /** A name for the key, unique to the user */
    name : string,
}

export function getJsonData(key : Key) : {[key:string]:any} {
    if (!key.data) return {}
    try {
        return JSON.parse(key.data);
    } catch {
        return {};
    }
}

/**
 * Describes a user as fetched from the user storage (eg, database table or LDAP),
 * 
 * This is extendible with additional keys - provide them to the {@link @crossauth/server!UserStorage} class as `extraFields`.
 * You may want to do this if you want to pass additional user data back to the caller, eg real name.
 */
export interface UserInputFields {
    username : string,
    state : string,
    [ key : string ] : any,
}
export interface User extends UserInputFields {
    id : string | number,
}

export interface UserSecretsInputFields {
    password? : string,
    totpSecret? : string,
    otp?: string,
    expiry?: number,
}

export interface UserSecrets extends UserSecretsInputFields {
    userId : string|number,
}

export interface OAuthClient {
    clientId : string,
    confidential : boolean,
    clientName : string,
    clientSecret? : string,
    redirectUri : string[],
    validFlow : string[],
    [ key : string ] : any,
}