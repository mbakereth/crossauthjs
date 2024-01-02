import { PrismaClient } from '@prisma/client';
import { UserStorage, UserPasswordStorage, KeyStorage } from '../storage';
import { User, UserWithPassword, Key } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface PrismaUserStorageOptions {
    userTable? : string,
    idColumn? : string,
    checkActive? : boolean,
    checkEmailVerified? : boolean,
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `user`.  It must have at least two fields:
 *    * `username String \@unique`
 *    * `passwordHash String`
 * `username` must have `\@unique`.  It must also contain an ID column, which is either an `Int` or `String`, eg
 *    * `id Int \@id \@unique \@default(autoincrement())
 * Alternatively you can set it to `username` if you don't have a separate ID field.
 * 
 * You can optionally check if an `active` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `active Boolean` field.
 *
 * You can optionally check if an `emailVerified` field is set to `true` when validating users,  Enabling this requires
 * the user table to also have an `emailVerified Boolean` field.
*/
export class PrismaUserStorage extends UserPasswordStorage {
    private userTable : string;
    private idColumn : string;
    private checkActive : boolean = false;
    private checkEmailVerified : boolean = false;
    private prismaClient : PrismaClient;

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param userTable the (Prisma, ie lowercase) name of the database table for storing users.  Defaults to `user`.
     * @param idColumn the column for the unique user ID.  May be a number of string.  Defaults to `id`.  May also be set to `username`.
     * @param checkActive if set to `true`, a user will only be returned as valid if the `active` field is `true`.  See explaination above.
     * @param checkEmailVerified if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
    */
    constructor({userTable,
                idColumn, 
                checkActive,
                checkEmailVerified,
                prismaClient} : PrismaUserStorageOptions = {}) {
        super();
        if (userTable) {
            this.userTable = userTable;
        } else {
            this.userTable = "user";
        }
        if (idColumn) {
            this.idColumn = idColumn;
        } else {
            this.idColumn = "id";
        }
        if (checkActive) {
            this.checkActive = checkActive;
        }
        if (checkEmailVerified) {
            this,checkEmailVerified = checkEmailVerified;
        }
        if (prismaClient) {
            this.prismaClient = prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
    }

    private async getUser(key : string, value : string | number, extraFields: string[]=[]) : Promise<UserWithPassword> {
        let error: CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [key]: value
                }
            });

            if (this.checkActive && !prismaUser["active"]) {
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if (this.checkEmailVerified && !prismaUser["emailVerified"]) {
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            let user : UserWithPassword = {
                id : prismaUser[this.idColumn],
                username : prismaUser.username,
                passwordHash : prismaUser.passwordHash
            }
            extraFields.forEach((key : string) => {
                user[key] = prismaUser[key];
            });

            return user;
        }  catch (e) {
            error = new CrossauthError(ErrorCode.UserNotExist); 
        }
        if (error) throw error;
        return {id: 0, username: "", passwordHash: ""}; // never reached but needed to shut typescript up
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @param extraFields these will be selected from the user table row and returned in the User object
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(username : string, extraFields: string[]=[]) : Promise<UserWithPassword> {
        return this.getUser("username", username, extraFields);
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @param extraFields these will be selected from the user table row and returned in the User object
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number, extraFields : string[]=[]) : Promise<UserWithPassword> {
        return this.getUser(this.idColumn, id, extraFields);
    }
}

/**
 * Optional parameters for {@link PrismaKeyStorage}.
 * 
 * See {@link PrismaKeyStorage.constructor} for definitions.
 */
export interface PrismaKeyStorageOptions {
    keyTable? : string,
    prismaClient? : PrismaClient,
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `session`.  It must have at least three fields:
 *    * `key String \@unique`
 *    * `user_id String or Int`
 *    * `dateCreated DateTime`
 *    * `expires DateTime`
 * `key` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userId` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PrismaUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 */
export class PrismaKeyStorage extends KeyStorage {
    private keyTable : string = "key";
    private userStorage : UserStorage
    private prismaClient : PrismaClient;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in Prisma, this may be an instance of {@link PrismaUserStorage } but any can be used.
     * @param keyTable the (Prisma, lowercased) name of the session table.  Defaults to `session`.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     */
    constructor(userStorage : UserStorage,
                {keyTable, 
                 prismaClient} : PrismaKeyStorageOptions = {}) {
        super();
        if (keyTable) {
            this.keyTable = keyTable;
        }
        this.userStorage = userStorage;
        if (prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = prismaClient;
        }
    }
    // throws UserNotExist, Connection
    /**
     * Returns the {@link User } and expiry date of the user matching the given session key, or throws an exception.
     * @param key the session key to look up in the session storage.
     * @param extraUserFields these will be selected from the user table row and returned in the User object
     * @param extraKeyFields these will be selected from the key table row and returned in the User object
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    async getUserForKey(key : string, 
        extraUserFields : string[] = [], 
        extraKeyFields : string[] = []) : Promise<{user: User, key : Key}> {
        let returnKey : Key = {value: "", dateCreated: new Date(), expires: undefined};
        let error : CrossauthError|undefined = undefined;
        let userId = 0;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKey =  await this.prismaClient[this.keyTable].findUniqueOrThrow({
                where: {
                    key: key
                }
            });
            returnKey = {
                value: prismaKey.key,
                dateCreated: prismaKey.dateCreated,
                expires: prismaKey.expires,
            }
            userId = prismaKey.user_id;

            extraKeyFields.forEach((key : string) => {
                returnKey[key] = prismaKey[key];
            });
        } catch {
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) throw error;
        try {
            let user = await this.userStorage.getUserById(userId, extraUserFields);
            return { user, key: returnKey };
        }  catch(e) {
            console.error(e);
            error = new CrossauthError(ErrorCode.UserNotExist); 
        }
        if (error) throw error;
        return {user: {id: 0, username: ""}, key: returnKey}; // never reached but needed to shut typescript up.
    }

    /**
     * Saves a key in the session table.
     * 
     * @param userId user ID to store with the session key.  See {@link PrismaUserStorage} for how this may differ from `username`.
     * @param key the key to store.
     * @param dateCreated the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will be stored in the key table row
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(userId : string | number, 
                      key : string, dateCreated : Date, 
                      expires : Date | undefined,
                      extraFields : {[key : string]: any} = {}) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        try {
            let data : {[key : string] : any} = {
                user_id : userId,
                key : key,
                created : dateCreated,
                expires : expires,
                ...extraFields,
            };

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].create({
                data: data
            })
        } catch (e) {
            error = new CrossauthError(ErrorCode.Connection, String(e));
        }
        if (error) throw error;
    }

    /**
     * 
     * @param key the key to delete
     * @throws {@link index!CrossauthError } if the key could not be deleted.
     */
    async deleteKey(key : string) : Promise<void> {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].deleteMany({
            where: {
                key: key
            }
        });
    }

}
