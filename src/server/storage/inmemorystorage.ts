import { UserStorage, UserPasswordStorage, SessionStorage } from '../storage';
import { User, UserWithPassword } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';

/**
 * Optional parameters for {@link InMemoryUserStorage}.
 * 
 * See {@link InMemoryUserStorage.constructor} for definitions.
 */
export interface InMemoryUserStorageOptions {
    checkActive? : boolean,
    checkEmailVerified? : boolean,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in memory.  It is really only
 * intended for testing.
 *  
 * You can optionally check if an `active` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `active Boolean` field.
 *
 * You can optionally check if an `emailVerified` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `emailVerified Boolean` field.
*/
export class InMemoryUserStorage extends UserPasswordStorage {
    usersByUsername : { [key : string]: UserWithPassword } = {};
    private checkActive : boolean = false;
    private checkEmailVerified : boolean = false;

    /**
     * Creates a InMemoryUserStorage object, optionally overriding defaults.
     * @param extraFields if set, these additional fields (an array of strings) will be created in the user table and returned in {@link UserWithPassword } instances.
     * @param checkActive if set to `true`, a user will only be returned as valid if the `active` field is `true`.  See explaination above.
     * @param checkEmailVerified if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
    */
    constructor({checkActive,
                checkEmailVerified} : InMemoryUserStorageOptions = {}) {
        super();
        if (checkActive) {
            this.checkActive = checkActive;
        }
        if (checkEmailVerified) {
            this,checkEmailVerified = checkEmailVerified;
        }
    }

    addUser(user : UserWithPassword) : void {
        this.usersByUsername[user.username] = {...user};
        user.passwordHash = "ABC";
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(username : string) : Promise<UserWithPassword> {
        if (username in this.usersByUsername) {

            const user = this.usersByUsername[username];
            if ('active' in user && user['active'] == false && this.checkActive) {
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if ('emailVerified' in user && user['emailVerified'] == false && this.checkEmailVerified) {
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            return {...user};
        }

        throw new CrossauthError(ErrorCode.UserNotExist);
    }

    /**
     * Same as {@link getUserByUsername } - userId is the username in this model,
     * @param id the user ID to match 
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string) : Promise<UserWithPassword> {
        return await this.getUserByUsername(id);
    }
}

/**
 * Implementation of {@link SessionStorage } where session keys stored in memory.  Intended for testing.
 */
export class InMemorySessionStorage extends SessionStorage {
    private userStorage : UserStorage
    private sessionByKey : { [key : string]: {
        userId : string,
        sessionKey : string,
        expires? : Date
    } } = {};

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in in memory, this may be an instance of {@link InMemoryUserStorage } but any can be used.
     */
    constructor(userStorage : UserStorage) {
        super();
        this.userStorage = userStorage;
    }

    /**
     * Returns the {@link User } and expiry date of the user matching the given session key, or throws an exception.
     * @param sessionKey the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    async getUserForSessionKey(sessionKey : string) : Promise<{user: User, expires : Date | undefined}> {
        if (sessionKey in this.sessionByKey) {
            let userId = this.sessionByKey[sessionKey].userId;
            let user = await this.userStorage.getUserById(userId);
            let expires = this.sessionByKey[sessionKey].expires;
            if (expires) {
                expires = new Date(expires.getTime());
            }
            return {user: {...user}, expires};
        }
        throw new CrossauthError(ErrorCode.InvalidSessionId); 
    }

    /**
     * Saves a session key in the session table.
     * 
     * @param uniqueUserId user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param sessionKey the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveSession(uniqueUserId : string, 
                      sessionKey : string, _dateCreated : Date, 
                      expires : Date | undefined) : Promise<void> {
        this.sessionByKey[sessionKey] = {
            sessionKey : sessionKey,
            userId : uniqueUserId,
            expires: expires
        };
    }

    /**
     * 
     * @param sessionKey the key to delete
     */
    async deleteSession(sessionKey : string) : Promise<void> {
        if (sessionKey in this.sessionByKey) {
            delete this.sessionByKey[sessionKey];
        }
    }

}
