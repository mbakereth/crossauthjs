import { UserStorage, UserPasswordStorage, KeyStorage } from '../storage';
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
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryKeyStorage extends KeyStorage {
    private userStorage : UserStorage
    private keys : { [key : string]: {
        userId : string,
        key : string,
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
     * Returns the {@link User } and expiry date of the user matching the given key, or throws an exception.
     * @param key the key to look up in the key storage.
     * @returns the {@link User } object for the user with the given key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getUserForKey(key : string) : Promise<{user: User, expires : Date | undefined}> {
        if (this.keys && key in this.keys) {
            let userId = this.keys[key].userId;
            let user = await this.userStorage.getUserById(userId);
            user = {...user};
            let expires = this.keys[key].expires;
            if (expires) {
                expires = new Date(expires.getTime());
            }
            if ("passwordHash" in user) {
                delete user.passwordHash;
            }
            return {user, expires};
        }
        throw new CrossauthError(ErrorCode.InvalidKey); 
    }

    /**
     * Saves a session key in the session table.
     * 
     * @param uniqueUserId user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param key the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(uniqueUserId : string, 
                      key : string, _dateCreated : Date, 
                      expires : Date | undefined) : Promise<void> {
        this.keys[key] = {
            key : key,
            userId : uniqueUserId,
            expires: expires
        };
    }

    /**
     * 
     * @param key the key to delete
     */
    async deleteKey(key : string) : Promise<void> {
        if (key in this.keys) {
            delete this.keys[key];
        }
    }

}
