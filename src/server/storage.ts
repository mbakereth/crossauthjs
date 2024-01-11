import { CrossauthError, ErrorCode } from '../error.ts';
import type { 
    User, UserWithPassword, Key
} from '../interfaces.ts';

/**
 * Base class for place where user details are stired,
 * 
 * This class is subclasses for various types of user storage,  Eg {@link PrismaUserStorage } is for storing
 * username and password in a database table, managed by the Prisma ORM.
 */
export abstract class UserStorage {
    /**
     * Returns user matching the given username, or throws an exception
     * @param username the username to return the user of
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserByUsername(username : string, skipEmailVerifiedCheck? : boolean) : Promise<User>;

    /**
     * Returns user matching the given user id, or throws an exception.
     * 
     * Not that implementations are free to define what the user ID is.  It can be a number of string,
     * or can simply be `username`.
     * 
     * @param id the user ID to return the user of
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserById(id : string | number, skipEmailVerifiedCheck? : boolean) : Promise<User>;

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
}

/**
 * Subcalsses {@link UserStorage } for cases where there is a username and password.
 */
export abstract class UserPasswordStorage extends UserStorage {

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param username the username to match
     */
    abstract getUserByUsername(username : string, skipEmailVerifiedCheck? : boolean) : Promise<UserWithPassword>;

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param id the user ID to match
     */
    abstract getUserById(id : string | number, skipEmailVerifiedCheck? : boolean) : Promise<UserWithPassword>;

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

