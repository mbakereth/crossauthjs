/**
 * A key (eg session ID) as stored in a key database table and send to the client as a cookie
 */
export interface Key {

    /** The key - in a cookie, the value part of cookiename=value; options... */
    value : string,

    /** The date the key was created, in local time on the server */
    created : Date,

    /** The date the key expires */
    expires : Date | undefined

    userId : string | number | undefined;

    [ key : string ] : any,
}

/**
 * Describes a user as fetched from the user storage (eg, database table or LDAP),
 * 
 * This is extendible with additional keys - provide them to the {@link server!UserStorage} class as `extraFields`.
 * You may want to do this if you want to pass additional user data back to the caller, eg real name.
 */
export interface User {
    id : string | number,
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

