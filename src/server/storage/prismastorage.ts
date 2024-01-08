import { PrismaClient, Prisma } from '@prisma/client';
import { UserStorage, UserPasswordStorage, KeyStorage } from '../storage';
import { User, UserWithPassword, Key } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger } from '../..';

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
    checkPasswordReset? : boolean,
    prismaClient? : PrismaClient,
    extraFields? : string[],
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
 * 
 * You can optionally check if a `passwordReset` field is set to `true` when validating users.  Enabling this requires
 * the user table to also have a `passwordReset Boolean` field.  Use this if you want to require your user to change his/her password.
*/
export class PrismaUserStorage extends UserPasswordStorage {
    private userTable : string = "user";
    private idColumn : string = "id";
    private checkActive : boolean = false;
    private checkEmailVerified : boolean = false;
    private checkPasswordReset : boolean = false;
    private prismaClient : PrismaClient;
    private extraFields? : string[];

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param userTable the (Prisma, ie lowercase) name of the database table for storing users.  Defaults to `user`.
     * @param idColumn the column for the unique user ID.  May be a number of string.  Defaults to `id`.  May also be set to `username`.
     * @param checkActive if set to `true`, a user will only be returned as valid if the `active` field is `true`.  See explaination above.
     * @param checkEmailVerified if set to `true`, a user will only be returned as valid if the `emailVerified` field is `true`.  See explaination above.
     * @param checkPasswordReset if set to true, a user will only be returned as valid if the "passwordReset" field is not `true`.  See explaination above.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     * @param extraFields if given, these additional fields will be selected from the table into the returned Key.
     */
    constructor({userTable,
                idColumn, 
                checkActive,
                checkEmailVerified,
                checkPasswordReset,
                prismaClient,
                extraFields} : PrismaUserStorageOptions = {}) {
        super();
        if (userTable)this.userTable = userTable;

        if(idColumn) this.idColumn = idColumn;

        if (checkActive)this.checkActive = checkActive;
        if (checkEmailVerified) this,checkEmailVerified = checkEmailVerified;
        if (checkPasswordReset) this,checkPasswordReset = checkPasswordReset;
        if (prismaClient) {
            this.prismaClient = prismaClient;
        } else {
            this.prismaClient = new PrismaClient();
        }
        this.extraFields = extraFields;
    }

    private async getUser(key : string, value : string | number) : Promise<UserWithPassword> {
        let error: CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [key]: value
                }
            });

            if (this.checkActive && !prismaUser["active"]) {
                CrossauthLogger.logger.debug("User has active set to false");
                throw new CrossauthError(ErrorCode.UserNotActive);
            }
            if (this.checkEmailVerified && !prismaUser["emailVerified"]) {
                CrossauthLogger.logger.debug("User has not verified email");
                throw new CrossauthError(ErrorCode.EmailNotVerified);
            }
            if (this.checkPasswordReset && !prismaUser["checkPasswordReset"]) {
                CrossauthLogger.logger.debug("User must reset password");
                throw new CrossauthError(ErrorCode.PasswordResetNeeded);
            }
            let user : UserWithPassword = {
                id : prismaUser[this.idColumn],
                username : prismaUser.username,
                passwordHash : prismaUser.passwordHash
            }
            if (this.extraFields) {
                this.extraFields.forEach((key : string) => {
                    user[key] = prismaUser[key];
                });
            }

            return user;
        }  catch (e) {
            error = new CrossauthError(ErrorCode.UserNotExist); 
        }
        if (error) {
            CrossauthLogger.logger.error(error);
            throw error;
        }
        return {id: 0, username: "", passwordHash: ""}; // never reached but needed to shut typescript up
    }

    /**
     * Returns a {@link UserWithPassword } instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @param extraFields these will be selected from the user table row and returned in the User object
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(username : string) : Promise<UserWithPassword> {
        return this.getUser("username", username);
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @param extraFields these will be selected from the user table row and returned in the User object
     * @returns a {@link UserWithPassword } instance, ie including the password hash.
     * @throws {@link index!CrossauthError } with {@link ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number) : Promise<UserWithPassword> {
        return this.getUser(this.idColumn, id);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        if (!(this.idColumn in user)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            const {id, ...data} = user;
            /*let data : {[key : string] : any} = {
                user_id : key.userId,
                created : key.created,
                expires : key.expires,
            };
            if ("lastActive" in key) {
                data = {...data, lastActive: key.lastActive};
            }*/

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.userTable].update({
                where: {
                    [this.idColumn]: user.id,
                },
                data: data
            });
        } catch (e) {
            error = new CrossauthError(ErrorCode.Connection, String(e));
        }
        if (error) {
            CrossauthLogger.logger.error(error);
            throw error;
        }
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
    extraFields? : string[],
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `session`.  It must have at least three fields:
 *    * `key String \@unique`
 *    * `user_id String or Int`
 *    * `created DateTime`
 *    * `expires DateTime`
 * `key` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userId` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PrismaUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 */
export class PrismaKeyStorage extends KeyStorage {
    private keyTable : string = "key";
    private prismaClient : PrismaClient;
    private extraFields? : string[];

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param userStorage an instance of {@link UserStorage } for fetching users.  If also in Prisma, this may be an instance of {@link PrismaUserStorage } but any can be used.
     * @param keyTable the (Prisma, lowercased) name of the session table.  Defaults to `session`.
     * @param prismaClient an instance of the prisma client to use.  If omitted, one will be created with defaults (ie `new PrismaClient()`).
     * @param extraFields if given, these additional fields will be selected from the table into the returned Key.
     */
    constructor({keyTable, 
                 prismaClient,
                extraFields} : PrismaKeyStorageOptions = {}) {
        super();
        if (keyTable) {
            this.keyTable = keyTable;
        }
        if (prismaClient == undefined) {
            this.prismaClient = new PrismaClient();
        } else {
            this.prismaClient = prismaClient;
        }
        this.extraFields = extraFields;
    }

    /**
     * Returns the matching Key record, or throws an exception if it doesn't exist
     * @param key the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link index!CrossauthError } instance with {@link ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    async getKey(key : string) : Promise<Key> {
        let returnKey : Key = {userId: 0, value: "", created: new Date(), expires: undefined};
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKey =  await this.prismaClient[this.keyTable].findUniqueOrThrow({
                where: {
                    key: key
                }
            });
            returnKey = {
                userId: prismaKey.user_id,
                value: prismaKey.key,
                created: prismaKey.created,
                expires: prismaKey.expires,
            }
            if (this.extraFields) {
                this.extraFields.forEach((key : string) => {
                    returnKey[key] = prismaKey[key];
                });
            }
        } catch {
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) {
            CrossauthLogger.logger.error(error);
            throw error;
        }
        return returnKey;
    }
    
    /**
     * Saves a key in the session table.
     * 
     * @param userId user ID to store with the session key.  See {@link PrismaUserStorage} for how this may differ from `username`.
     * @param key the key to store.
     * @param created the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will be stored in the key table row
     * @throws {@link index!CrossauthError } if the key could not be stored.
     */
    async saveKey(userId : string | number | undefined, 
                      key : string, created : Date, 
                      expires : Date | undefined,
                      extraFields : {[key : string]: any} = {}) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        try {
            let data : {[key : string] : any} = {
                user_id : userId,
                key : key,
                created : created,
                expires : expires,
                ...extraFields,
            };

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].create({
                data: data
            })
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError) {
                const pe = e as Prisma.PrismaClientKnownRequestError;
                if (pe.code == 'P2002') {
                    CrossauthLogger.logger.debug("Attempt to create key that already exists. Stack trace follows");
                    CrossauthLogger.logger.debug(pe);
                    error = new CrossauthError(ErrorCode.KeyExists);
                } else {
                    CrossauthLogger.logger.debug(e);
                    error = new CrossauthError(ErrorCode.Connection, String(e));
                }
            error = new CrossauthError(ErrorCode.Connection, String(e));
            }
        }
        if (error) {
            CrossauthLogger.logger.error(error);
            throw error;
        }
    }

    /**
     * 
     * @param key the key to delete
     * @throws {@link index!CrossauthError } if the key could not be deleted.
     */
    async deleteKey(key : string) : Promise<void> {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
            where: {
                key: key
            }
        });
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userId : user ID to delete keys for
     */
    async deleteAllForUser(userId : string | number, except : string|undefined = undefined) : Promise<void> {
        if (except) {
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: [
                        { user_id: userId },
                        { key: { not: except } }
                    ]
                }
            });

        } else {
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    user_id: userId 
                }
            });
        }
    }     

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key 
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        if (!(key.value)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            let data = {...key};
            data.delete("value");
            /*let data : {[key : string] : any} = {
                user_id : key.userId,
                created : key.created,
                expires : key.expires,
            };
            if ("lastActive" in key) {
                data = {...data, lastActive: key.lastActive};
            }*/

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].update({
                where: {
                    key: key.value,
                },
                data: data
            });
        } catch (e) {
            error = new CrossauthError(ErrorCode.Connection, String(e));
        }
        if (error) {
            CrossauthLogger.logger.error(error);
            throw error;
        }
    }
}
