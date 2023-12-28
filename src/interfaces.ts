/**
 * A session key as stored in a session database table and send to the client as a cookie
 */
export interface SessionKey {

    /** The session key - the value part of SESSIONID=value; options... */
    value : string,

    /** The date the session key was created, in local time on the server */
    dateCreated : Date,

    /** The date the session key expires */
    expires : Date | undefined
}

/**
 * Describes a user as fetched from the user storage (eg, database table or LDAP),
 * 
 * This is extendible with additional keys - provide them to the {@link server!UserStorage} class as `extraFields`.
 * You may want to do this if you want to pass additional user data back to the caller, eg real name.
 */
export interface User {
    uniqueId : string | number,
    username : string,
    [ key : string ] : any,
}

/**
 * Extends the {@link User} interface to also require a password.  Used as input to functions that
 * perform password authentication
 */
export interface UserWithPassword extends User {
    /** 
     * Password in PBKPDF2 hashed form, with the algorithm, iterations, etc.  
     * See {@link server!HashedPasswordAuthenticator.decodePasswordHash} 
     */
    passwordHash : string
}

