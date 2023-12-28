import type { 
    User, UserWithPassword, 
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
    abstract getUserByUsername(username : string) : Promise<User>;

    /**
     * Returns user matching the given user id, or throws an exception.
     * 
     * Not that implementations are free to define what the user ID is.  It can be a number of string,
     * or can simply be `username`.
     * 
     * @param id the user ID to return the user of
     * @throws CrossauthException with ErrorCode either `UserNotExist` or `Connection`
     */
    abstract getUserById(id : string | number) : Promise<User>;
}

/**
 * Subcalsses {@link UserStorage } for cases where there is a username and password.
 */
export abstract class UserPasswordStorage extends UserStorage {

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param username the username to match
     */
    abstract getUserByUsername(username : string) : Promise<UserWithPassword>;

    /**
     * Same as for base class but returns {@link UserWithPassword} instead.
     * @param id the user ID to match
     */
    abstract getUserById(id : string | number) : Promise<UserWithPassword>;

}

/**
 * Base class for storing session keys.
 *
 * This class is subclasses for various types of session key storage,  Eg {@link PrismaSessionStorage } is for storing
 * session in a database table, managed by the Prisma ORM.
 */
export abstract class SessionStorage {
    // throws InvalidSessionId

    /**
     * Returns the user matching the given session key, or throws an exception
     * @param sessionKey the session key to look up
     * @returns An object containing the user and the date the session key expires (if it exists).  The password hash will not be returned,
     * @throws {@link index!CrossauthError } with {@link index!ErrorCode } of `InvalidSessionId` if a match was not found in session storage.
     */
    abstract getUserForSessionKey(sessionKey : string) : Promise<{user: User, expires : Date | undefined}>;

    /**
     * Saves a session key in the session storage (eg database).
     * 
     * @param uniqueUserId the ID of the user.  This matches the primary key in the {@link UserStorage } implementation.
     * @param sessionKey the session key to store.
     * @param dateCreated the date/time the session key was created.
     * @param expires the date/time the session key expires.
     */
    abstract saveSession(uniqueUserId : string | number, 
                         sessionKey : string, 
                         dateCreated : Date, 
                         expires : Date | undefined) : Promise<void>;

    /**
     * Deletes a session key from session storage (eg the database).
     * 
     * @param sessionKey the session key to delete
     */
    abstract deleteSession(sessionKey : string) : Promise<void>;
}

