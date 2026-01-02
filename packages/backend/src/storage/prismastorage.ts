// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { PrismaClient, Prisma } from '../lib/generated/prisma/client';
import { UserStorage, KeyStorage, type UserStorageGetOptions, type UserStorageOptions, OAuthClientStorage, type OAuthClientStorageOptions, OAuthAuthorizationStorage } from '../storage';
import { type User, type UserSecrets, type UserInputFields, type UserSecretsInputFields, type Key, type OAuthClient } from '@crossauth/common';
import { CrossauthError, ErrorCode, OAuthFlows } from'@crossauth/common';
import { CrossauthLogger, j, UserState } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface PrismaUserStorageOptions extends UserStorageOptions {

    /** Name of user table (to Prisma, ie lowercase).  Default `user` */
    userTable? : string,

    /** Name of user secrets table (to Prisma, ie lowercase).  Default `userSecrets` */
    userSecretsTable? : string,

    /** Name of the id column in the user table.  Can be set to `username` if that is your primary key.
     * Default `id`.
     */
    idColumn? : string,

    /** Name of the user id column in the user secrets.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,

    /** The prisma client instance.  Leave this out to have Crossauth create a default one */
    prismaClient? : any; // PrismaClient,

    includes? : string[];

    /**
     * This works around a Fastify and Sveltekit limitation.  If the id passed to 
     * getUserById() is a string but is numeric, first try forcing it to
     * a number before selecting.  If that fails, try it as the string,
     * Default true.
     */
    forceIdToNumber? : boolean,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `user`.  It must have at least these fields:
 *    * `username String \@unique`
 *    * `username_normalized String \@unique`
 *    * `state String`
 * It must also contain an ID column, which is either an `Int` or `String`, eg
 *    * `id Int \@id \@unique \@default(autoincrement())
 * Alternatively you can set it to `username` if you don't have a separate ID field.
 *
 * You can optionally check if the `state` field is set to `awaitingemailverification` when validating users.
 *  If the username is not the email address,
 *  it must contain these extra two fields:
 *     * `email String \@unique`
 *     * `email_normalized String \@unique`
 * 
 * You can optionally check if a `passwordReset` field is set to `true` when validating users.  Enabling this requires
 * the user table to also have a `passwordReset Boolean` field.  Use this if you want to require your user to change his/her password.
 * 
 * If `normalizeUsername` is true, getting a user by username will match on normalized (converting dialetics)
 * and lowercased username.  This is not true of matching by id, even if the id columns is the same as the username column.
 * 
 * If `normalizeEmail` is true, getting a user by username will matched on normalized, lowercase username.
*/
export class PrismaUserStorage extends UserStorage {
    private userTable : string = "user";
    private userSecretsTable : string = "userSecrets";
    private idColumn : string = "id";
    private useridForeignKeyColumn : string = "userid";
    private prismaClient : PrismaClient;
    private includes : string[] = ["secrets"];
    private includesObject : {[key:string]:boolean} = {};
    private forceIdToNumber : boolean = true;

    /**
     * Creates a PrismaUserStorage object, optionally overriding defaults.
     * @param options see {@link PrismaUserStorageOptions}
     */
    constructor(options : PrismaUserStorageOptions = {}) {
        super(options);
        setParameter("userTable", ParamType.String, this, options, "USER_TABLE");
        setParameter("userSecretsTable", ParamType.String, this, options, "USER_SECRETS_TABLE");
        setParameter("idColumn", ParamType.String, this, options, "USER_ID_COLUMN");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        setParameter("includes", ParamType.String, this, options, "USER_INCLUDES");
        setParameter("forceIdToNumber", ParamType.String, this, options, "USER_FORCE_ID_TO_NUMBER");
	    this.includes.forEach((item) => {this.includesObject[item] = true});

        if (options && options.prismaClient) {
            this.prismaClient = options.prismaClient;
        } else {
            const connectionString = `${process.env.DATABASE_URL}`;
            const adapter = new PrismaBetterSqlite3({ url: connectionString });
            this.prismaClient = new PrismaClient({adapter});
        }
    }

    private async getUser(
        normalizedKey : string, 
        normalizedValue : string | number,
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        let error: CrossauthError|undefined = undefined;
        let prismaUser : any;
        if (!this.prismaClient) {
            error = new CrossauthError(ErrorCode.Connection); 
        }
        if (error) throw error;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            prismaUser = await this.prismaClient[this.userTable].findUniqueOrThrow({
                where: {
                    [normalizedKey]: normalizedValue
                },
                include: this.includesObject,
            });

        }  catch (e) {
            //if (e instanceof Prisma.PrismaClientKnownRequestError) {
            if (typeof(e) == "object" && e?.constructor.name == "PrismaClientInitializationError") {
                CrossauthLogger.logger.debug(j({err: e}))
                CrossauthLogger.logger.error(j({cerr: e}))
                error = new CrossauthError(ErrorCode.Connection, "Couldn't connect to database server"); 
            }
            else if (typeof(e) == "object" && e?.constructor.name == "PrismaClientInitializationError") {
                CrossauthLogger.logger.debug(j({err: e}))
                CrossauthLogger.logger.error(j({cerr: e}))
                error = new CrossauthError(ErrorCode.Connection, "Received error from database"); 
            } else {
                error = new CrossauthError(ErrorCode.UserNotExist); 
            }
        }
        if (error) throw error;
        
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.awaitingTwoFactorSetup) {
            CrossauthLogger.logger.debug(j({msg: "2FA setup is not complete"}));
            throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.disabled) {
            CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
            throw new CrossauthError(ErrorCode.UserNotActive);
        }
        if (options?.skipEmailVerifiedCheck!=true && prismaUser["state"]==UserState.awaitingEmailVerification) {
            CrossauthLogger.logger.debug(j({msg: "User has not verified email"}));
            throw new CrossauthError(ErrorCode.EmailNotVerified);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"] == UserState.passwordChangeNeeded) {
            CrossauthLogger.logger.debug(j({msg: "User must change password"}));
            throw new CrossauthError(ErrorCode.PasswordChangeNeeded);
        }
        if (options?.skipActiveCheck!=true && (prismaUser["state"] == UserState.passwordResetNeeded || prismaUser["state"] == UserState.passwordAndFactor2ResetNeeded)) {
            CrossauthLogger.logger.debug(j({msg: "User must reset password"}));
            throw new CrossauthError(ErrorCode.PasswordResetNeeded);
        }
        if (options?.skipActiveCheck!=true && prismaUser["state"]==UserState.factor2ResetNeeded) {
            CrossauthLogger.logger.debug(j({msg: "2FA reset required"}));
            throw new CrossauthError(ErrorCode.Factor2ResetNeeded);
        }
        const secrets = prismaUser.secrets || {};
        if (prismaUser.secrets) {
            delete secrets[this.useridForeignKeyColumn];
            delete prismaUser.secrets;
        }
        return {user: {...prismaUser, id: prismaUser[this.idColumn]}, secrets: {userid: prismaUser[this.idColumn], ...secrets}};
    }

    /**
     * Returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance matching the given username, or throws an Exception.
     * @param username the username to look up
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByUsername(
        username : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            if (this.normalizeUsername) {
                const normalizedValue = PrismaUserStorage.normalize(username);
                return this.getUser("username_normalized", normalizedValue, options);
            } else {
                const normalizedValue = username;
                return this.getUser("username", normalizedValue, options);
            }
    }

    /**
     * Returns user matching the given field, or throws an exception.  
     * 
     * @param field the field to match
     * @param value the value to match (case sensitive)
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or whatever pg throws
     */
    async getUserBy(
        field : string, 
        value : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return this.getUser(field, value, options);
        }

    /**
     * Returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance matching the given email address, or throws an Exception.
     * 
     * If there is no email field in the user, the username is assumed to contain the email
     * 
     * @param email the email address to look up
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserByEmail(
        email : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        if (this.normalizeEmail) {
            const normalizedValue = PrismaUserStorage.normalize(email);
            return this.getUser("email_normalized", normalizedValue, options);
        } else {
            const normalizedValue = email;
            return this.getUser("email", normalizedValue, options);
        }
    }

    /**
     * Same as {@link getUserByUsername } but matching user ID,
     * @param id the user ID to match 
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or `Connection`.
     */
    async getUserById(id : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        if (this.forceIdToNumber && typeof(id) == "string" && id.match(/^[+-]?[0-9]+$/)) {
            try {
                return await this.getUser(this.idColumn, Number(id), options);
            } catch (e) {
                const ce = CrossauthError.asCrossauthError(e);
                if (ce.code == ErrorCode.UserNotExist) {
                    return await this.getUser(this.idColumn, id, options);
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw e;
                }
            }
        }
        return await this.getUser(this.idColumn, id, options);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * 
     * Warning: the fields in `user` and `secrets` are not validated so, before calling this,
     * you should check they are in `userEditableFields`.
     * 
     * @param user the user to update.  The id to update is taken from this obkect, which must be present.  All other attributes are optional. 
     */
    async updateUser(user : Partial<User>, secrets?: Partial<UserSecrets>) : Promise<void> {
        //if (!(this.idColumn in user)) throw new CrossauthError(ErrorCode.InvalidKey);
        if (!(user.id)) throw new CrossauthError(ErrorCode.InvalidKey);
        //if (secrets && !secrets.userid) secrets.userid = user[this.idColumn];
        if (secrets && !secrets.userid) secrets = {...secrets, userid: user[this.idColumn]};
        try {
            let {id: dummyUserId, ...userData} = user;
            let {userid: dummySecretsId, ...secretsData} = secrets??{};
            if ("email" in userData && userData.email && this.normalizeEmail) {
                userData = {email_normalized: PrismaUserStorage.normalize(userData.email), ...userData};
            }
            if ("username" in userData && userData.username && this.normalizeUsername) {
                userData = {username_normalized: PrismaUserStorage.normalize(userData.username), ...userData};
            }
            if (!secrets) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.userTable].update({
                    where: {
                        [this.idColumn]: user.id,
                    },
                    data: userData,
                });
            } else {
                await this.prismaClient.$transaction(async (tx: any) =>{

                    let existingSecrets : {[key:string]:any} = {}
                    try {
                        // @ts-ignore  (because types only exist when do prismaClient.table...)
                        existingSecrets = await tx[this.userSecretsTable].findUniqueOrThrow({
                            where: {
                                [this.useridForeignKeyColumn]: user.id
                            },
                        });
                    } catch (e) {}
                    let {userid: dummySecretsId, ...existingSecretsData} = existingSecrets??{};
                    secretsData = {...existingSecretsData, ...secretsData}
                    // @ts-ignore
                    await tx[this.userTable].update({
                        where: {
                            [this.idColumn]: user.id,
                        },
                        data: {
                            ...userData,
                        },
                    });

                    // @ts-ignore
                    await tx[this.userSecretsTable].upsert({
                        where: {
                            [this.useridForeignKeyColumn]: user.id,
                        },
                        update: 
                            secretsData,
                        create:
                            {[this.useridForeignKeyColumn]: user.id,
                            ...secretsData
                            }
                    });
                });
            }
        } catch (e) {
            console.log(e)
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating user");
        }
    }

    /**
     * Create a user
     * 
     * Warning: the fields in `user` and `secrets` are not validated so, before calling this,
     * you should check they are in `userEditableFields`.
     * 
     * @param user 
     * @param secrets 
     */
    async createUser(user: UserInputFields, secrets? : UserSecretsInputFields)
               : Promise<User> {
        let error : CrossauthError|undefined = undefined;
        if (secrets && !secrets.password) throw new CrossauthError(ErrorCode.PasswordFormat, "Password required when creating user");
        let newUser;
        let username_normalized = "";
        let email_normalized = "";
        try {
            if ("email" in user && user.email && this.normalizeEmail) {
                email_normalized = PrismaUserStorage.normalize(user.email);
            }
            if ("username" in user && user.username && this.normalizeUsername) {
                username_normalized = PrismaUserStorage.normalize(user.username);
            }
            let data : {[key:string]:any} = {
                    ...user,
            }
            if (this.normalizeUsername) {
                data = {
                    ...data,
                    username_normalized
                }
            }
            if (this.normalizeEmail) {
                data = {
                    ...data,
                    email_normalized
                }
            }
            if (secrets) {

                data = {
                    ...data,
                    secrets: { 
                        create: 
                            secrets
                    }
                }

                // @ts-ignore  (because types only exist when do prismaClient.table...)
                newUser = await this.prismaClient[this.userTable].create({
                    data,
                    include: { secrets: true},
                });
            } else {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                newUser = await this.prismaClient[this.userTable].create({
                        data,
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error creating user");
            if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                if (e.code === 'P2002') {
                    error = new CrossauthError(ErrorCode.UserExists);
                }
            }
        }
        if (error) {
            throw error;
        }
        return newUser;
    }

   async  deleteUserByUsername(username : string) : Promise<void>  {
    let error : CrossauthError;
    try {
        // @ts-ignore  (because types only exist when do prismaClient.table...)
        return /*await*/ this.prismaClient[this.userTable].deleteMany({
        where: {
            username: username
        }
    });
    } catch (e) {
        CrossauthLogger.logger.debug(j({err: e}));
        error = new CrossauthError(ErrorCode.Connection, "Error deleting user");
    } 
    if (error) throw error;

   }

   async deleteUserById(id : string|number) : Promise<void>  {
        if (this.forceIdToNumber && typeof(id) == "string" && id.match(/^[+-]?[0-9]+$/)) {
            try {
                return await this.deleteUserById_internal(Number(id));
            } catch (e) {
                CrossauthLogger.logger.debug(j({msg: "Failed forcing id to number when deleting user"}));
            }
        }
        return await this.deleteUserById_internal(id);
    }

   private async deleteUserById_internal(id : string|number) : Promise<void>  {
    let error : CrossauthError;
    try {
        // @ts-ignore  (because types only exist when do prismaClient.table...)
        return /*await*/ this.prismaClient[this.userTable].delete({
        where: {
            id: id
        }
    });
    } catch (e) {
        CrossauthLogger.logger.debug(j({err: e}));
        error = new CrossauthError(ErrorCode.Connection, "Error deleting user");
    } 
    if (error) throw error;

   }

    async getUsers(skip? : number, take? : number) : Promise<User[]> {
        let opts : {[key:string]:number} = {};
        if (skip) opts.skip = skip;
        if (take) opts.take = take;

        let order_by = this.normalizeUsername ? "username_normalized" : "username";
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            return await this.prismaClient[this.userTable].findMany({
                ...opts,
                orderBy: [
                    {
                        [order_by]: 'asc',
                    },
                ],
                include: this.includesObject,
            });
        }  catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Couldn't select from user table")
        }
        
    }


}

///////////////////////////////////////////////////////////////////////////
// KeyStorage

/**
 * Optional parameters for {@link PrismaKeyStorage}.
 * 
 * See {@link PrismaKeyStorage.constructor} for definitions.
 */
export interface PrismaKeyStorageOptions {
    keyTable? : string,
    prismaClient? : any,
    transactionTimeout? : number,
    /** Name of the user id column in the user secrets.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a database managed by
 * the Prisma ORM.
 * 
 * By default, the Prisma name (ie the lowercased version) is called `key`.  It must have at least three fields:
 *    * `value String \@unique`
 *    * `userid String or Int`
 *    * `created DateTime`
 *    * `expires DateTime`
 * `key` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userid` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PrismaUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 */
export class PrismaKeyStorage extends KeyStorage {
    private keyTable : string = "key";
    private prismaClient : PrismaClient;
    private transactionTimeout = 5_000;
    private useridForeignKeyColumn : string = "userid";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaKeyStorageOptions}
     */
    constructor(options : PrismaKeyStorageOptions = {}) {
        super();
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        setParameter("useridForeignKeyColumn", ParamType.Number, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        if (options.keyTable) {
            this.keyTable = options.keyTable;
        }
        if (options.prismaClient == undefined) {
            const connectionString = `${process.env.DATABASE_URL}`;
            const adapter = new PrismaBetterSqlite3({ url: connectionString });
            this.prismaClient = new PrismaClient({adapter});
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getKey(key : string) : Promise<Key> {
        return await this.getKeyWithTransaction(key, this.prismaClient);
    }

    /**
     * Returns the matching Key record, or throws an exception if it doesn't exist
     * @param key the session key to look up in the session storage.
     * @returns the {@link User } object for the user with the given session key, with the password hash removed, as well as the expiry date/time of the key.
     * @throws a {@link @crossauth/common!CrossauthError } instance with {@link @crossauth/common!ErrorCode} of `InvalidSession`, `UserNotExist` or `Connection`
     */
    private async getKeyWithTransaction(key : string, tx : any) : Promise<Key> {
        let returnKey : Key = {userid: 0, value: "", created: new Date(), expires: undefined};
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKey =  await tx[this.keyTable].findUniqueOrThrow({
                where: {
                    value: key
                }
            });
            returnKey = {
                ...prismaKey,
                userid: prismaKey[this.useridForeignKeyColumn],
            }
            if (this.useridForeignKeyColumn != "userid") {
                delete returnKey[this.useridForeignKeyColumn]
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) {
            throw error;
        }
        return returnKey;
    }
    
    /**
     * Saves a key in the session table.
     * 
     * @param userid user ID to store with the session key.  See {@link PrismaUserStorage} for how this may differ from `username`.
     * @param value the value of the key to store.
     * @param created the date/time the key was created.
     * @param expires the date/time the key expires.
     * @param extraFields these will be stored in the key table row
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be stored.
     */
    async saveKey(userid : string | number | undefined, 
                      value : string, created : Date, 
                      expires : Date | undefined,
                      data? : string,
                      extraFields : {[key : string]: any} = {}) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        try {
            let prismaData : {[key : string] : any} = {
                [this.useridForeignKeyColumn] : userid,
                value : value,
                created : created,
                expires : expires??null,
                data : data,
                ...extraFields,
            };

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await this.prismaClient[this.keyTable].create({
                data: prismaData
            })
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                if (e.code == 'P2002') {
                    CrossauthLogger.logger.warn(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
                    CrossauthLogger.logger.debug(j({err: e}));
                    error = new CrossauthError(ErrorCode.KeyExists);
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    error = new CrossauthError(ErrorCode.Connection, "Error saving key");
                }
            } else {
                CrossauthLogger.logger.debug(j({err: e}));
                error = new CrossauthError(ErrorCode.Connection, "Error saving key");
            }
        }
        if (error) {
            throw error;
        }
    }

    /**
     * 
     * @param value the value of the key to delete
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be deleted.
     */
    async deleteKey(value : string) : Promise<void> {
        let error : CrossauthError;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
            where: {
                value: value
            }
        });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }

    /**
     * Deletes all keys from storage for the given user ID
     * 
     * @param userid : user ID to delete keys for
     */
    async deleteAllForUser(userid : string | number | undefined, prefix : string, except? : string) : Promise<void> {
        let error : CrossauthError;
        try {
            if (except) {
                // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
                return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                    where: {
                        AND: [
                            { [this.useridForeignKeyColumn]: userid??null },
                            { value: {startsWith: prefix} },
                            { value: { not: except } },
                        ]
                    }
                });

            } else {
                // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
                return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                    where: {
                        AND: [
                            { [this.useridForeignKeyColumn]: userid??null },
                            { value: {startsWith: prefix} } ,
                        ]
                    }
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }     

    async deleteMatching(key : Partial<Key>) : Promise<void> {
        try {
            let andClause = [];
            for (let entry in key) {
                if (entry == "userid") {
                    andClause.push({[this.useridForeignKeyColumn]: key[entry]});

                } else {
                    andClause.push({[entry]: key[entry]});
                }
            }
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: andClause,
                }
            });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error deleting keys");
        }
}

    /**
     * Deletes all keys with the given prefix
     * 
     * @param userid : user ID to delete keys for
     */
    async deleteWithPrefix(userid : string | number | undefined, prefix : string) : Promise<void> {
        let error : CrossauthError;
        try {
            // @ts-ignore - because referring to a table name in a variable doesn't have a type in Prisma
            return /*await*/ this.prismaClient[this.keyTable].deleteMany({
                where: {
                    AND: [
                        { [this.useridForeignKeyColumn]: userid??null },
                        { value: {startsWith: prefix} },
                    ]
                }
            });

        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            error = new CrossauthError(ErrorCode.Connection, "Error deleting key");
        } 
        if (error) throw error;
    }     

    async getAllForUser(userid : string|number|undefined) : Promise<Key[]> {
        let returnKeys : Key[] = [];
        let error : CrossauthError|undefined = undefined;
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let prismaKeys =  await this.prismaClient[this.keyTable].findMany({
                where: {
                    [this.useridForeignKeyColumn]: userid??null
                }
            });
            returnKeys = prismaKeys.map((v : Partial<Key>) => { 
                let ret = {...v, userid: v[this.useridForeignKeyColumn]}; 
                if (this.useridForeignKeyColumn!="userid") {
                    // @ts-ignore
                    delete ret[this.useridForeignKeyColumn]; 
                }
                return ret; });
        } catch {
            error = new CrossauthError(ErrorCode.InvalidKey);
        }
        if (error) {
            throw error;
        }
        return returnKeys;

    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key the new values of the key.   `value` must be set and will not be updated.
     *        any other fields set (not undefined) will be updated.
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        await this.updateKeyWithTransaction(key, this.prismaClient);
    }

    private async updateKeyWithTransaction(key : Partial<Key>, tx : any) : Promise<void> {
        let error : CrossauthError|undefined = undefined;
        if (!(key.value)) throw new CrossauthError(ErrorCode.InvalidKey);
        try {
            let data = {...key};
            delete data.value;

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.keyTable].update({
                where: {
                    value: key.value,
                },
                data: data
            });
        } catch (e) {
            error = new CrossauthError(ErrorCode.Connection, String(e));
        }
        if (error) {
            CrossauthLogger.logger.debug(j({err: error}));
            throw error;
        }
    }

    /**
     * See {@link KeyStorage}.
     */
    async updateData(keyName : string, dataName: string, value: any|undefined) : Promise<void> {
        return await this.updateManyData(keyName, [{dataName, value}]);
    }

    /**
     * See {@link KeyStorage}.
     */
    async updateManyData(keyName : string, dataArray: [{dataName: string, value: any|undefined}]) : Promise<void> {
        try {

            await this.prismaClient.$transaction(async (tx: any) =>{
                const key = await this.getKeyWithTransaction(keyName, tx);
                let data : {[key:string] : any};
                if (!key.data || key.data == "") {
                    data = {}
                } else {
                    try {
                        data = JSON.parse(key.data);
                    } catch (e) {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.DataFormat);
                    }
                }   
                for (let item of dataArray) {
                    let ret = this.updateDataInternal(data, item.dataName, item.value);
                    if (!ret) throw new CrossauthError(ErrorCode.BadRequest, `Parents of ${item.dataName} not found in key data`);
                    data = ret;    
                }
            
                await this.updateKeyWithTransaction({value: key.value, data: JSON.stringify(data)}, tx)
            }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating session data");
            }
            throw e;
        }

                  
    }
    /**
     * See {@link KeyStorage}.
     */
    async deleteData(keyName : string, dataName: string) : Promise<void> {
        try {

            let changed = false;
            await this.prismaClient.$transaction(async (tx: any) =>{
                let data : {[key:string] : any} = {};
                const key = await this.getKeyWithTransaction(keyName, tx);
                if (key.data && key.data != "") {
                    try {
                        data = JSON.parse(key.data);
                    } catch (e) {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.DataFormat);
                    }
                    changed = this.deleteDataInternal(data, dataName);
                }   
                if (changed)
                    await this.updateKeyWithTransaction({value: key.value, data: JSON.stringify(data)}, tx)
            }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating session data");
            }
            throw e;
        }

                  
    }
}

///////////////////////////////////////////////////////////////////////////
// OAuthClientStorage

/**
 * Optional parameters for {@link PrismaOAuthClientStorage}.
 */
export interface PrismaOAuthClientStorageOptions extends OAuthClientStorageOptions {

    /** Prisma name of the OAuth Client table.  Default oAuthClient */
    clientTable? : string,

    /** Prisma name of the OAuth valid flows table.  Default oClientValidFlow */
    validFlowTable? : string,

    /** Prisma name of the OAuth Redirect Uri table.  Default oAuthClientRedirectUri */
    redirectUriTable? : string,

    /** A Prisma client to use.  If not provided, one will be created */
    prismaClient? : any; // PrismaClient,

    /** In milliseconds.. Default 5000 */
    transactionTimeout? : number,

    /**
     * This is to work around a Prisma bug.  SQLite returns an error
     * when updating a client if inside a transaction.  
     * - `Update` `OAuthClient` table is updated, `OAuthClientAuthorization`
     *            and `OAuthValidFlow` are updated with a delete and insert.
     *            Doesn't work with SQLite.
     * - `DeleteAndInsert` updated to the `OAuthClient`, 
     *                     `OAuthClientAuthorization` and `OAuthValidFlow` are
     *                     all done as a delete then an insert.  Works for
     *                     SQLite but if you have cascading dependencies on
     *                     the `OAuthClient` table, dependent rows will be
     *                     deleted.
     * Our recommendation is to use `DeleteAndInsert` for SQLite and 
     * `Update` otherwise.
     * 
     * Default `DeleteAndInsert`
     */
    updateMode? : "Update" | "DeleteAndInsert",

    /** Name of the user id column in the user secrets.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,
}

/**
 * Implementation of {@link OAuthClientStorage } where clients stored in a database managed by
 * the Prisma ORM.
 */
export class PrismaOAuthClientStorage extends OAuthClientStorage {
    private clientTable : string = "oAuthClient";
    private redirectUriTable : string = "OAuthClientRedirectUri";
    private validFlowTable : string = "OAuthClientValidFlow";
    private prismaClient : any;// PrismaClient;
    private transactionTimeout = 5_000;
    private updateMode = "DeleteAndInsert";
    private useridForeignKeyColumn = "userid";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(options : PrismaOAuthClientStorageOptions = {}) {
        super();
        setParameter("clientTable", ParamType.String, this, options, "OAUTH_CLIENT_TABLE");
        setParameter("redirectUriTable", ParamType.String, this, options, "OAUTH_REDIRECTURI_TABLE");
        setParameter("validFlowTable", ParamType.String, this, options, "OAUTH_VALID_FLOW_TABLE");
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        setParameter("updateMode", ParamType.String, this, options, "OAUTHCLIENT_UPDATE_MODE");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        if (options.prismaClient == undefined) {
            const connectionString = `${process.env.DATABASE_URL}`;
            const adapter = new PrismaBetterSqlite3({ url: connectionString });
            this.prismaClient = new PrismaClient({adapter});
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getClientById(client_id : string) : Promise<OAuthClient> {
        return (await this.getClientWithTransaction("client_id", client_id, this.prismaClient, true, undefined))[0];
    }

    async getClientByName(name : string, userid? : string|number|null) : Promise<OAuthClient[]> {
        return await this.getClientWithTransaction("client_name", name, this.prismaClient, false, userid);
    }

    private async getClientWithTransaction(field : string, value : string, tx : any, unique : boolean, userid : string|number|null|undefined) : Promise<OAuthClient[]> {
        const userWhere = (userid == undefined && !(userid === null)) ? {} : {[this.useridForeignKeyColumn]: userid};
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            if (unique) {
                const client = await tx[this.clientTable].findUniqueOrThrow({
                    where: {
                        [field]: value,
                        ...userWhere,
                    },
                    include: {redirect_uri: true, valid_flow: true},
                });
                const redirect_uriObjects = client.redirect_uri;
                const valid_flowObjects = client.valid_flow;
                let userid = client[this.useridForeignKeyColumn];
                if (userid === null) userid = undefined;
                if (this.useridForeignKeyColumn != "userid") delete client[this.useridForeignKeyColumn];
                return [{
                    ...client, 
                    userid : userid,
                    client_secret: client.client_secret??undefined, 
                    redirect_uri: redirect_uriObjects.map((x:{[key:string]:any}) => x.uri), 
                    valid_flow: valid_flowObjects.map((x:{[key:string]:any}) => x.flow)
                }];
            } else {
                const clients = await tx[this.clientTable].findMany({
                    where: {
                        [field]: value,
                        ...userWhere,
                    },
                    include: {redirect_uri: true, valid_flow: true},
                });
                for (let client of clients) {
                    const redirect_uriObjects = client.redirect_uri;
                    const valid_flowObjects = client.valid_flow;
                    let userid = client[this.useridForeignKeyColumn];
                    if (userid == null) userid = undefined;    
                    client.userid = userid;
                    if (this.useridForeignKeyColumn != "userid")  delete client[this.useridForeignKeyColumn];
                    client.client_secret = client.client_secret??undefined;
                    client.redirect_uri = redirect_uriObjects.map((x:{[key:string]:any}) => x.uri);
                    client.valid_flow = valid_flowObjects.map((x:{[key:string]:any}) => x.flow)
                }
                return clients;
                }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            CrossauthLogger.logger.error(j({msg: "Invalid OAuth client", [field]: value, cerr: e}))
            throw new CrossauthError(ErrorCode.InvalidClientId);
        }
    }

    /**
     * Saves a key in the session table.
     * 
     * @param client fields for the client to create
     * @throws {@link @crossauth/common!CrossauthError } if the client could not be stored.
     */
    async createClient(client : OAuthClient) : Promise<OAuthClient> {
        try {
            return this.prismaClient.$transaction(async (tx: any) => {
                try {
                    await this.getClientWithTransaction("client_id", client.client_id, tx, true, client.userid);
                    throw new CrossauthError(ErrorCode.ClientExists);
                } catch (e1) {}
                return await this.createClientWithTransaction(client, tx);
            }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed creating client");
            }
            throw e;
        }
    }

    private async createClientWithTransaction(client : OAuthClient, tx : any) : Promise<OAuthClient> {
        const {redirect_uri, valid_flow, userid, ...prismaClientData} = client;
        let newClient : OAuthClient|undefined;
        if (userid) prismaClientData[this.useridForeignKeyColumn] = userid;
        if (this.useridForeignKeyColumn != "userid") delete client[this.useridForeignKeyColumn];
        // validate redirect uri
        if (redirect_uri) {
            for (let i=0; i<redirect_uri.length; ++i) {
                if (redirect_uri[i].includes("#")) throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Redirect Uri's may not contain page fragments");
                try {
                    new URL(redirect_uri[i]);
                }
                catch (e) {
                    throw new CrossauthError(ErrorCode.InvalidRedirectUri, `Redriect uri ${redirect_uri[i]} is not valid`);
                }
            }
        }

        // validate valid flows
        if (valid_flow) {
            for (let i=0; i<valid_flow.length; ++i) {
                if (!OAuthFlows.isValidFlow(valid_flow[i])) throw new CrossauthError(ErrorCode.InvalidOAuthFlow, "Invalid flow " + valid_flow[i]);
            }
        }

        
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            newClient = await tx[this.clientTable].create({
                data: prismaClientData,
            });
        } catch (e) {
            if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                if (e.code == 'P2002') {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.ClientExists, "Attempt to create an OAuth client with a client_id that already exists. Maximum attempts failed");
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            } else {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");

            }
        }
        if (!newClient) {
            CrossauthLogger.logger.error(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
            throw new CrossauthError(ErrorCode.KeyExists);    
        }

        // create redirect uris
        if (redirect_uri) {
            try {
                for (let i=0; i<redirect_uri.length; ++i) {
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.redirectUriTable].create({
                        data: {
                            client_id: newClient.client_id,
                            uri: redirect_uri[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    if (e.code == 'P2002') {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Attempt to create an OAuth client with a redirect uri that already belongs to another client");
                    } else {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            }
        }

        // create valid flows
        if (valid_flow) {
            try {
                for (let i=0; i<valid_flow.length; ++i) {
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.validFlowTable].create({
                        data: {
                            client_id: newClient.client_id,
                            flow: valid_flow[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
                }
            }
        }

        return {...newClient, redirect_uri: redirect_uri, valid_flow: valid_flow};
    }

    /**
     * 
     * @param client_id the client to delete
     * @throws {@link @crossauth/common!CrossauthError } if the key could not be deleted.
     */
    async deleteClient(client_id : string) : Promise<void> {
        try {
            //return await this.updateClientWithTransaction(client, this.prismaClient);
                return this.prismaClient.$transaction(async (tx: any) => {
            return await this.deleteClientWithTransaction(client_id, tx);
        }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed deleting client");
            }
            throw e;
        }
    }


    private async deleteClientWithTransaction(client_id : string, tx : any) : Promise<void> {
            try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.clientTable].deleteMany({
            where: {
                client_id: client_id
            }
        });
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error deleting OAuth client");
        } 
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param client the client to update.  It will be searched on its client_id, which cannot be updated.
     */
    async updateClient(client : Partial<OAuthClient>) : Promise<void> {
        try {
            //return await this.updateClientWithTransaction(client, this.prismaClient);
                return this.prismaClient.$transaction(async (tx:any) => {
            return this.updateMode == "Update" ? 
                 await this.updateClientWithTransaction_update(client, tx) :
                 await this.updateClientWithTransaction_deleteAndInsert(client, tx);
        }, {timeout: this.transactionTimeout});
        } catch (e) {
            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating client");
            }
            throw e;
        }
    }

    // This gives a Rust error when used with a transaction on SQLlite

    private async updateClientWithTransaction_update(client : Partial<OAuthClient>, tx : any) : Promise<void> {
        if (!(client.client_id)) throw new CrossauthError(ErrorCode.InvalidClientId);
        const redirect_uris = client.redirect_uri;
        const validFlows = client.valid_flow;

        // validate redirect uris
        if (redirect_uris) {
            for (let i=0; i<redirect_uris.length; ++i) {
                if (redirect_uris[i].includes("#")) throw new CrossauthError(ErrorCode.InvalidRedirectUri, "Redirect Uri's may not contain page fragments");
                try {
                    new URL(redirect_uris[i]);
                }
                catch (e) {
                    throw new CrossauthError(ErrorCode.InvalidRedirectUri, `Redriect uri ${redirect_uris[i]} is not valid`);
                }
            }
        }
        

        // validate valid flows
        if (validFlows) {
            for (let i=0; i<validFlows.length; ++i) {
                if (!OAuthFlows.isValidFlow(validFlows[i])) throw new CrossauthError(ErrorCode.InvalidOAuthFlow, "Redirect Uri's may not contain page fragments");
            }
        }
    
        try {
            let data = {...client};
            delete data.client_id;
            delete data.redirect_uri;
            delete data.valid_flow;
            if ("userid" in data &&this.useridForeignKeyColumn != "userid") {
                data[this.useridForeignKeyColumn] = data.userid;
                delete data.userid;
            }

            if (Object.keys(data).length > 0) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await tx[this.clientTable].update({
                    where: {
                        client_id: client.client_id,
                    },
                    data: data
                });
            }
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating client");
        }

        if (redirect_uris != undefined) {
            try {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.redirectUriTable].deleteMany({
                        where: {
                        client_id: client.client_id
                    }
                });
                for (let i=0; i<redirect_uris.length; ++i) { 
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.redirectUriTable].create({
                        data: {
                            client_id: client.client_id,
                            uri: redirect_uris[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    if (e.code == 'P2002') {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.KeyExists, "Attempt to update an OAuth client with a redirect Uri that already belongs to another client");
                    } else {
                        CrossauthLogger.logger.debug(j({err: e}));
                        throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                    }
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                }
            }    
        }

        if (validFlows != undefined) {
            try {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                await this.prismaClient[this.validFlowTable].deleteMany({
                    where: {
                        client_id: client.client_id
                    }
                });
                for (let i=0; i<validFlows.length; ++i) { 
                    // @ts-ignore  (because types only exist when do prismaClient.table...)
                    await tx[this.validFlowTable].create({
                        data: {
                            client_id: client.client_id,
                            flow: validFlows[i],
                        }
                    });
                }
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError || (e instanceof Object && "code" in e)) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                } else {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Error updating client");
                }
            }    
        }

    }

    private async updateClientWithTransaction_deleteAndInsert(client : Partial<OAuthClient>, tx : any) : Promise<void> {
        if (!(client.client_id)) throw new CrossauthError(ErrorCode.InvalidClientId);
        const existingClient = (await this.getClientWithTransaction("client_id", client.client_id, this.prismaClient, true, undefined))[0];
        const newClient = {...existingClient, ...client};
        if ("userid" in newClient && this.useridForeignKeyColumn != "userid") {
            newClient[this.useridForeignKeyColumn] = newClient.userid;
            delete newClient.userid;
        }
        await this.deleteClientWithTransaction(client.client_id, tx);
        await this.createClientWithTransaction(newClient, tx);
    }

    async getClients(skip? : number, take? : number, userid? : string|number|null) : Promise<OAuthClient[]> {
        let opts : {[key:string]:number} = {};
        if (skip) opts.skip = skip;
        if (take) opts.take = take;

        try {
            let clients : OAuthClient[] = [];
            if (userid || userid === null) {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                clients = await this.prismaClient[this.clientTable].findMany({
                    ...opts,
                    where: {
                        [this.useridForeignKeyColumn]: userid,
                    },
                    orderBy: [
                        {
                            client_name: 'asc',
                        },
                    ],
                });
            } else {
                // @ts-ignore  (because types only exist when do prismaClient.table...)
                clients = await this.prismaClient[this.clientTable].findMany({
                    ...opts,
                    orderBy: [
                        {
                            client_name: 'asc',
                        },
                    ],
                });
            } 

            clients.forEach((client) => {
                if (this.useridForeignKeyColumn != "userid") {
                    client.userid = client[this.useridForeignKeyColumn];
                    delete client[this.useridForeignKeyColumn];
                }
                client.userid = client.userid===null ? undefined : client.userid; 
                return client});
            return clients;
        }  catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Couldn't select from client table")
        }
        
    }
}

///////////////////////////////////////////////////////////////////////////
// OAuthAuthorizationStorage

/**
 * Optional parameters for {@link PrismaOAuthAuthorizationStorage}.
 */
export interface PrismaOAuthAuthorizationStorageOptions extends OAuthClientStorageOptions {

    /** Prisma name of the OAuth Authorization table.  Default oAuthAuthorization */
    authorizationTable? : string,

    /** A Prisma client to use.  If not provided, one will be created */
    prismaClient? : any; // PrismaClient,

    transactionTimeout? : number,

    /** Name of the user id column in the table.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,
}

/**
 * Implementation of {@link OAuthAuthorizationStorage } where authorizations are stored in a database managed by
 * the Prisma ORM.
 */
export class PrismaOAuthAuthorizationStorage extends OAuthAuthorizationStorage {
    private authorizationTable : string = "oAuthAuthorization";
    private prismaClient : any;// PrismaClient;
    private transactionTimeout : number = 5_000;
    private useridForeignKeyColumn = "userid";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(options : PrismaOAuthClientStorageOptions = {}) {
        super();
        setParameter("authorizationTable", ParamType.String, this, options, "OAUTH_AUTHORIZATION_TABLE");
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        if (options.prismaClient == undefined) {
            const connectionString = `${process.env.DATABASE_URL}`;
            const adapter = new PrismaBetterSqlite3({ url: connectionString });
            this.prismaClient = new PrismaClient({adapter});
        } else {
            this.prismaClient = options.prismaClient;
        }
    }

    async getAuthorizations(client_id : string, userid : string|number|undefined) : Promise<(string|null)[]> {
        try {
            // @ts-ignore  (because types only exist when do prismaClient.table...)
            let rows = await this.prismaClient[this.authorizationTable].findMany({
                where: {
                    client_id : client_id,
                    [this.useridForeignKeyColumn]: userid??null,
                },
                select: {
                    scope: true,
                },
        });
            return rows.map((row : {[key:string]:any}) => row.scope);
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            //CrossauthLogger.logger.error(j({msg: "Couldn't get authorizations", client_id: client_id, userid: userid, cerr: e}))
            throw new CrossauthError(ErrorCode.Connection);
        }
    }

    async updateAuthorizations(client_id : string, userid : string|number|null, scopes : string[]) : Promise<void> {
        return this.prismaClient.$transaction(async (tx:any) => {
            return await this.updateAuthorizationsWithTransaction(client_id, userid, scopes, tx);
        }, {timeout: this.transactionTimeout});
    }

    /**
     * Saves a key in the session table.
     * 
     * @param client_id the client to update
     * @param userid the user ID to associate with the client, or undefined
     *        for a client not associated with a user
     * @param scopes the scopes that are authorized (new plus existing)
     * @throws {@link @crossauth/common!CrossauthError } if the client could not be stored.
     */
    private async updateAuthorizationsWithTransaction(client_id : string, userid : string|number|null, scopes : string[], tx : any) : Promise<void> {

        try {
            // delete existing authorizations

            // @ts-ignore  (because types only exist when do prismaClient.table...)
            await tx[this.authorizationTable].deleteMany({
                where: {
                    client_id: client_id,
                    [this.useridForeignKeyColumn] : userid??null
                }
            });

            // add new authorizations
            const promises : Promise<void>[] = [];
            scopes.forEach((scope) => {
                promises.push(tx[this.authorizationTable].create({
                    data: {
                        client_id : client_id,
                        [this.useridForeignKeyColumn] : userid??null,
                        scope : scope,
                    },
                }));
            });
            await Promise.all(promises);
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            throw new CrossauthError(ErrorCode.Connection, "Error updating OAuth authorizations");
        } 
    }
}
