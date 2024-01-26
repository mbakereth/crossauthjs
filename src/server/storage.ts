import { CrossauthError, ErrorCode } from '../error.ts';
import { setParameter, ParamType } from './utils';
import type { User, UserSecrets, Key, UserInputFields, UserSecretsInputFields } from '../interfaces.ts';

export interface UserStorageGetOptions {
    skipEmailVerifiedCheck? : boolean
    skipActiveCheck? : boolean
}

export interface PrismaUserStorageOptions {
	userEditableFields? : string[],
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
    readonly userEditableFields : string[] = [];

    constructor(options : PrismaUserStorageOptions = {}) {
        setParameter("userEditableFields", ParamType.StringArray, this, options, "USER_EDITABLE_FIELDS");
    }
    
    /**
     * Returns user matching the given username, or throws an exception.  
     * 
     * The username should be matched normalized and lowercased (using normalize())
     * @param username the username to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByUsername(
        username : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * Returns user matching the given user id, or throws an exception.
     * 
     * Not that implementations are free to define what the user ID is.  It can be a number of string,
     * or can simply be `username`.
     * 
     * @param id the user id to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserById(
        id : string|number, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * Returns user matching the given email address, or throws an exception.
     * 
     * The email should be matched normalized and lowercased (using normalize())
     * If the email field doesn't exist, username is assumed to be the email column
     * 
     * @param email the email address to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByEmail(
        email : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}>;

    /**
     * If you enable signup, you will need to implement this method
     */
    createUser(_user : UserInputFields, _secrets : UserSecretsInputFields) 
        : Promise<User> {
        throw new CrossauthError(ErrorCode.Configuration);
    }

    /**
     * If the given user exists in the database, update it with the passed values.  If it doesn't
     * exist, throw a CrossauthError with InvalidKey.
     * @param user  The id field must be set, but all others are optional 
     */
    abstract updateUser(user : Partial<User>, secrets? : Partial<UserSecrets>) : Promise<void>;

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
    static normalize(str : string) : string {
        return str.normalize("NFD").replace(/\p{Diacritic}/gu, "").toLowerCase();
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
    abstract deleteAllForUser(userId : string | number, prefix : string, except? : string) : Promise<void>;

}

