import { CrossauthError, ErrorCode } from '../error.ts';
import type { 
    User, UserWithPassword, Key
} from '../interfaces.ts';

export interface UserStorageGetOptions {
    skipEmailVerifiedCheck? : boolean
    skipActiveCheck? : boolean
}

/**
 * Base class for place where user details are stired,
 * 
 * This class is subclasses for various types of user storage,  Eg {@link PrismaUserStorage } is for storing
 * username and password in a database table, managed by the Prisma ORM.
 * 
 * Username and email searches should be case insensitive, as should their unique constraints.  id searches
 * need not be case insensitive .
 */
export abstract class UserStorage {
    /**
     * Returns user matching the given username, or throws an exception.  
     * 
     * The username should be matched normalized and lowercased (using normalize())
     * @param username the username to return the user of
     * @param extraFields extra fields to select (in addition to any pre-configured ones)
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByUsername(
        username : string, 
         extraFields? : string[],
         options? : UserStorageGetOptions) : Promise<User>;

    /**
     * Returns user matching the given user id, or throws an exception.
     * 
     * Not that implementations are free to define what the user ID is.  It can be a number of string,
     * or can simply be `username`.
     * 
     * @param id the user id to return the user of
     * @param options optionally turn off checks.  Used internally
     * @param extraFields extra fields to select (in addition to any pre-configured ones)
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserById(
        id : string|number, 
         extraFields? : string[],
         options? : UserStorageGetOptions) : Promise<User>;

    /**
     * Returns user matching the given email address, or throws an exception.
     * 
     * The email should be matched normalized and lowercased (using normalize())
     * If the email field doesn't exist, username is assumed to be the email column
     * 
     * @param email the email address to return the user of
     * @param options optionally turn off checks.  Used internally
     * @param extraFields extra fields to select (in addition to any pre-configured ones)
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByEmail(
        email : string | number, 
        extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<User>;

    /**
     * If you enable signup, you will need to implement this method
     */
    createUser(_username : string, _passwordHash : string, _extraFields : {[key : string]: string|number|boolean|Date|undefined}) 
        : Promise<string|number> {
        throw new CrossauthError(ErrorCode.Configuration);
    }

    /**
     * If the given user exists in the database, update it with the passed values.  If it doesn't
     * exist, throw a CrossauthError with InvalidKey.
     * @param user  The id field must be set, but all others are optional 
     */
    abstract updateUser(user : Partial<User>) : Promise<void>;

    /**
     * If your storage supports this, delete the named user from storage.
     * @param username username to delete
     */
    abstract deleteUserByUsername(username : string) : Promise<void>;

    /**
     * Usernames and emails are stored in lowercase, normalized format.  This function returns that normalization
     * @param str the string to normalize
     * @returns the normalized string, in lowercase with diacritics removed
     */
    static normalize(str : string) {
        return str.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
    }
}

/**
 * Subcalsses {@link UserStorage } for cases where there is a username and password.
 */
export abstract class UserPasswordStorage extends UserStorage {

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param username the username to match
     */
    abstract getUserByUsername(
        username : string, 
        extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<UserWithPassword>;

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param id the user ID to match
     */
    abstract getUserById(id : string | number, 
        extraFields? : string[],
        options? : UserStorageGetOptions) : Promise<UserWithPassword>;

    /**
     * Removes the passwordHash field from the user object
     * 
     * Doesn't change the passed user object, just removes it from a copy.
     * 
     * @param user the user object to remove password from
     * @returns a new User object without passwordHash
     */
    static removePasswordHash(user : User) {
        const { passwordHash, ...rest} = user;
        return rest;
    }
}

/**
 * Base class for storing session and API keys.
 *
 * This class is subclasses for various types of session key storage,  Eg {@link PrismaKeyStorage } is for storing
 * session in a database table, managed by the Prisma ORM.
 */
export abstract class KeyStorage {
    // throws InvalidSessionId

    /**
     * Returns the matching key in the session storage or throws an exception if it doesn't exist.
     * 
     * @param key the key to look up
     * @returns The matching Key record.
     * @throws {@link index!CrossauthError } with {@link index!ErrorCode } of `InvalidSessionId` if a match was not found in session storage.
     */
    abstract getKey(key : string) : Promise<Key>;

    /**
     * Saves a session key in the session storage (eg database).
     * 
     * @param userId the ID of the user.  This matches the primary key in the {@link UserStorage } implementation.
     * @param key the key key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param data an optional value, specific to the type of key, eg new email for email change tokens
     * @param extraFields these will be stored in the key storage entry
     */
    abstract saveKey(userId : string | number | undefined, 
                         key : string, 
                         dateCreated : Date, 
                         expires : Date | undefined, 
                         data? : string,
                         extraFields? : {[key : string]: any}) : Promise<void>;


    /**
     * If the given session key exists in the database, update it with the passed values.  If it doesn't
     * exist, throw a CrossauthError with InvalidKey.
     * @param key 
     */
    abstract updateKey(key : Partial<Key>) : Promise<void>;

    /**
     * Deletes a key from storage (eg the database).
     * 
     * @param key the key to delete
     */
    abstract deleteKey(key : string) : Promise<void>;

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    abstract deleteAllForUser(userId : string | number, except? : string) : Promise<void>;
}

