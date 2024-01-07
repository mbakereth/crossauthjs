import { UserStorage, UserPasswordStorage, KeyStorage } from '../storage';
import { UserWithPassword, Key } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger } from '../..';
import type { User } from '../..';

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
 * intended for testing and is not thread safe.
 * 
 * There is no separate ID field - it is set to username.
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
     * 
     * @param username the username to look up
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist`.
     */
    async getUserByUsername(username : string) : Promise<UserWithPassword> {
        if (username in this.usersByUsername) {

            const user = this.usersByUsername[username];
            if ('active' in user && user['active'] == false && this.checkActive) {
                CrossauthLogger.logger.debug("User has active set to false");
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if ('emailVerified' in user && user['emailVerified'] == false && this.checkEmailVerified) {
                CrossauthLogger.logger.debug("User email not verified");
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            return {...user};
        }

        CrossauthLogger.logger.debug("User does not exist");
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

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>) : Promise<void> {
        if (user.id && user.id in this.usersByUsername) {
            let id : string|number = user.id||"";
            for (let field in user) {
                this.usersByUsername[id][field] = user[field];
            }
        }
    }
}

/**
 * Implementation of {@link KeyStorage } where keys stored in memory.  Intended for testing.
 */
export class InMemoryKeyStorage extends KeyStorage {
    private keys : { [key : string]: Key } = {};

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in in memory, this may be an instance of {@link InMemoryUserStorage } but any can be used.
     */
    constructor() {
        super();
    }

    /**
     * Returns the matching key recortd, with additional, or throws an exception.
     * @param key the key to look up in the key storage.
     * @returns the matching Key record
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidKey`, `UserNotExist` or `Connection`
     */
    async getKey(key : string) : Promise<Key> {
        if (this.keys && key in this.keys) {
            return this.keys[key];
        }
        CrossauthLogger.logger.debug("Key does not exist in key storage.  Stack trace follows");
        let err = new CrossauthError(ErrorCode.InvalidKey); 
        CrossauthLogger.logger.debug(err.stack);
        throw err;
    }

    /**
     * Saves a session key in the session table.
     * 
     * @param uniqueUserId user ID to store with the session key.  See {@link InMemoryUserStorage} for how this may differ from `username`.
     * @param key the session key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will also be stored in the key table row
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(uniqueUserId : string, 
                      key : string, dateCreated : Date, 
                      expires : Date | undefined, 
                      extraFields? : {[key : string]: any}) : Promise<void> {
        this.keys[key] = {
            value : key,
            userId : uniqueUserId,
            created: dateCreated,
            expires: expires,
            ...extraFields
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

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteAllForUser(userId : string | number, except : string|undefined = undefined) : Promise<void> {
       for (const key in this.keys) {
            if (this.keys[key].userId == userId && (!except || key != except)) delete  this.keys[key];
       }
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key 
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        if (key.value && key.value in this.keys) {
            let value : string = key.value||"";
            for (let field in key) {
                this.keys[value] = key[field];
            }
        }
    }


}
