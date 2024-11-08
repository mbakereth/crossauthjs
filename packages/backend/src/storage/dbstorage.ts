// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { DbPool, DbConnection } from './dbconnection';
import {
    UserStorage,
    KeyStorage,
    type UserStorageGetOptions,
    type UserStorageOptions,
    OAuthClientStorage,
    type OAuthClientStorageOptions,
    OAuthAuthorizationStorage } from '../storage';
import {
    type User,
    type UserSecrets,
    type Key,
    type UserInputFields,
    type UserSecretsInputFields,
    type OAuthClient,
    OAuthFlows } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j, UserState } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';

///////////////////////////////////////////////////////////////////////////
// UserStorage

/**
 * Optional parameters for {@link DbUserStorage}.
 * 
 * See {@link DbUserStorage.constructor} for definitions.
 */
export interface DbUserStorageOptions extends UserStorageOptions {
    /** Name of user table.  Default `users` */
    userTable? : string,

    /** Name of user secrets table Default `usersecrets` */
    userSecretsTable? : string,

    /** Name of the id column in the user table.  Can be set to `username` if that is your primary key.
     * Default `id`.
     */
    idColumn? : string,

    /** Name of the user id column in the user secrets.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,

    /**
     * This works around a Fastify and Sveltekit limitation.  If the id passed to 
     * getUserById() is a string but is numeric, first try forcing it to
     * a number before selecting.  If that fails, try it as the string.
     * Default true.
     */
    forceIdToNumber? : boolean,
}

/**
 * Implementation of {@link UserStorage} where username and password is stored 
 * in two database tables: one for non secret fields, one for secret fields.
 * 
 * The database engine is abstracted out.  Instead of using this class,
 * use a subclass such as {@link PostgresUserTable}, etc.
 * 
 * By default, the table is called `users`  It must have at least these fields:
 *    * `username String \@unique`
 *    * `username_normalized String \@unique`
 *    * `state String`
 * It must also contain an ID column, which is either an integer or string type, eg
 *    * `id serial primary key`
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
 * If `normalitzEmail` is true, getting a user by username will matched on normalized, lowercase username.
 * 
 * Some database engines are case insensitve by default whereas Typescript isn't.  If you
 * create your tables with case-sensitive names, these will be returned as-is.
 * If you create them with case insensitive names (the default) but you have
 * the name with a different case in your input, it will be returned as
 * lowercase from the database.  Therefore if you do not explicitly create
 * your tables with uppercase columns, make sure any field you pass in the
 * {@link @crossauth/common!User} or {@link @crossauth/common!UserSecrets} is
 * lowercase.
 */
export class DbUserStorage extends UserStorage {
    private userTable : string = "users";
    private userSecretsTable : string = "usersecrets";
    private idColumn : string = "id";
    private useridForeignKeyColumn = "userid";
    private forceIdToNumber : boolean = true;
    private dbPool : DbPool;
    /**
     * Creates a DbUserStorage object, optionally overriding defaults.
     * @param dbPool the instance of the Posrgres client. 
     * @param options see {@link DbUserStorageOptions}.
     */
    constructor(dbPool : DbPool, options : DbUserStorageOptions = {}) {
        super(options);
        this.dbPool = dbPool;

        setParameter("userTable", ParamType.String, this, options, "USER_TABLE");
        setParameter("userSecretsTable", ParamType.String, this, options, "USER_SECRETS_TABLE");
        setParameter("idColumn", ParamType.String, this, options, "USER_ID_COLUMN");
        setParameter("forceIdToNumber", ParamType.String, this, options, "USER_FORCE_ID_TO_NUMBER");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
    }

    /**
     * Returns user matching the given id, or throws an exception.  
     * 
     * @param id the id to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or whatever pg throws
     */
    async getUserById(
        id : string|number, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.getUser(this.idColumn, id, options);
    }

    /**
     * Returns user matching the given username, or throws an exception.  
     * 
     * Matches on the normalized username if `normalizeUsername` is true.
     * @param username the username to return the user of
     * @param options optionally turn off checks.  Used internally
     * @throws CrossauthException with ErrorCode either `UserNotExist` or whatever pg throws
     */
    async getUserByUsername(
        username : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            const normalizedValue = this.normalizeUsername ?  DbUserStorage.normalize(username) : username;
            return await this.getUser("username_normalized", normalizedValue, options);
    }

    /**
     * Returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance matching the given email address, or throws an Exception.
     * 
     * If there is no email field in the user, the username is assumed to contain the email
     * 
     * @param email the email address to look up
     * @returns a {@link @crossauth/common!User} and {@link @crossauth/common!UserSecrets} instance, ie including the password hash.
     * @throws {@link @crossauth/common!CrossauthError } with {@link @crossauth/common!ErrorCode } set to either `UserNotExist` or whatever pg throwsa.
     */
    async getUserByEmail(
        email : string, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
        const normalizedValue = this.normalizeEmail ? DbUserStorage.normalize(email) : email;
        return this.getUser("email_normalized", normalizedValue, options);
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
            return await this.getUser(field, value, options);
    }

    private async getUser(
        field : string,
        value : string|number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {

            let dbClient = await this.dbPool.connect();

            let user : User|undefined = undefined;
            let secrets : UserSecrets|undefined = undefined;
            let params = this.dbPool.parameters();
            try {
                await dbClient.startTransaction();

                // get user
                let query = `select * from ${this.userTable} where ${field} = ` + params.nextParameter();
                let res = await dbClient.execute(query, [value]);
                if (res.length == 0) {
                    throw new CrossauthError(ErrorCode.UserNotExist);
                }
                let id : string|number;
                let username : string;
                let state : string;
                if (this.idColumn in res[0]) id = res[0][this.idColumn];
                else throw new CrossauthError(ErrorCode.Configuration, "ID column " + this.idColumn + " not present in user table");
                if ("username" in res[0]) username = res[0]["username"];
                else throw new CrossauthError(ErrorCode.Configuration, "username column " + this.idColumn + " not present in user table");
                if ("state" in res[0]) state = res[0]["state"];
                else throw new CrossauthError(ErrorCode.Configuration, "state column " + this.idColumn + " not present in user table");
                
                user = {
                    ...res[0],
                    id,
                    username,
                    state
                };
                if (!user) throw new CrossauthError(ErrorCode.UserNotExist);

                // get secrets
                params = this.dbPool.parameters();
                query = `select * from ${this.userSecretsTable} where ${this.useridForeignKeyColumn} = ` + params.nextParameter();
                res = await dbClient.execute(query, [user.id]);
                    if (res.length == 0) {
                    throw new CrossauthError(ErrorCode.UserNotExist);
                }
                if (res.length > 0) secrets = {userid: user.id, ...res[0]};
                else secrets = {userid: user.id};
                if (!secrets) throw new CrossauthError(ErrorCode.UserNotExist);;
                if (this.useridForeignKeyColumn != "userid" && this.useridForeignKeyColumn in secrets) delete secrets[this.useridForeignKeyColumn];

                await dbClient.commit();

                if (options?.skipActiveCheck!=true && user["state"]==UserState.awaitingTwoFactorSetup) {
                    CrossauthLogger.logger.debug(j({msg: "2FA setup is not complete"}));
                    throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
                }
                if (options?.skipActiveCheck!=true && user["state"]==UserState.disabled) {
                    CrossauthLogger.logger.debug(j({msg: "User is deactivated"}));
                    throw new CrossauthError(ErrorCode.UserNotActive);
                }
                if (options?.skipEmailVerifiedCheck!=true && user["state"]==UserState.awaitingEmailVerification) {
                    CrossauthLogger.logger.debug(j({msg: "User has not verified email"}));
                    throw new CrossauthError(ErrorCode.EmailNotVerified);
                }
                if (options?.skipActiveCheck!=true && user["state"] == UserState.passwordChangeNeeded) {
                    CrossauthLogger.logger.debug(j({msg: "User must change password"}));
                    throw new CrossauthError(ErrorCode.PasswordChangeNeeded);
                }
                if (options?.skipActiveCheck!=true && (user["state"] == UserState.passwordResetNeeded || user["state"] == UserState.passwordAndFactor2ResetNeeded)) {
                    CrossauthLogger.logger.debug(j({msg: "User must reset password"}));
                    throw new CrossauthError(ErrorCode.PasswordResetNeeded);
                }
                if (options?.skipActiveCheck!=true && user["state"]==UserState.factor2ResetNeeded) {
                    CrossauthLogger.logger.debug(j({msg: "2FA reset required"}));
                    throw new CrossauthError(ErrorCode.Factor2ResetNeeded);
                }

                return {user, secrets};
            } catch (e) {
                await dbClient.rollback();
                throw e
            } finally {
                dbClient.release();
            }
              
    }

    /**
     * Returns all users, regardless of their status, ordered by username
     * @param skip limit to this many records returned
     * @param take skip this nuber of records from the start
     * @returns 
     */
    async getUsers(skip? : number, take? : number) : Promise<User[]> {

        const dbClient = await this.dbPool.connect();

        let users : User[] = [];
        let values : any[] = [];
        let limit = "";
        let offset = "";
        let params = this.dbPool.parameters();
        if (skip) {
            offset = "OFFSET " + params.nextParameter();
        }
        if (take) {
            values.push(take);
            limit = "LIMIT " + params.nextParameter();
        }

        try {

            // get user
            let query =  `select * from ${this.userTable} ${limit} ${offset} order by username_normalized asc`;
            let res = await dbClient.execute(query, values);
                if (res.length == 0) {
                throw new CrossauthError(ErrorCode.UserNotExist);
            }

            for (let user of res) {
                let id : string|number;
                let username : string;
                let state : string;
                if (this.idColumn in user) id = user[this.idColumn];
                else throw new CrossauthError(ErrorCode.Configuration, "ID column " + this.idColumn + " not present in user table");
                if ("username" in user) username = user["username"];
                else throw new CrossauthError(ErrorCode.Configuration, "username column " + this.idColumn + " not present in user table");
                if ("state" in user) state = user["state"];
                else throw new CrossauthError(ErrorCode.Configuration, "state column " + this.idColumn + " not present in user table");
                let newUser = {
                    ...user,
                    id,
                    username,
                    state
                };
                users.push(newUser)
            }
            return users;
        } catch (e) {
            throw e
        } finally {
            dbClient.release()
        }
              
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

        if (!(this.idColumn in user)) throw new CrossauthError(ErrorCode.InvalidKey);
        if (secrets && !secrets.userid) secrets = {...secrets, userid: user[this.idColumn]};
        if (secrets && this.useridForeignKeyColumn != "userid" && this.useridForeignKeyColumn in secrets) delete secrets[this.useridForeignKeyColumn];

        const dbClient = await this.dbPool.connect();

        try {
            await dbClient.startTransaction();

            // check user exists
            let params = this.dbPool.parameters();
            let query = `select * from ${this.userTable} where ${this.idColumn} = ` + params.nextParameter();
            let userRes = await dbClient.execute(query, [user.id]);
                if (userRes.length == 0) {
                throw new CrossauthError(ErrorCode.UserNotExist);
            }

            let userData = {...user};
            let secretsData = secrets? {...secrets} : undefined;
            if ("email" in userData && userData.email) {
                userData = {email_normalized: this.normalizeEmail ? DbUserStorage.normalize(userData.email) : userData.email, ...userData};
            }
            if ("username" in userData && userData.username) {
                userData = {username_normalized: this.normalizeUsername ? DbUserStorage.normalize(userData.username) : userData.username, ...userData};
            }

            // update user
            params = this.dbPool.parameters();
            let setFields : string[] = [];
            let values: any[] = [];
            for (let field in userData) {
                if (userData[field] != undefined && field != "id") {
                    setFields.push(field + "= " + params.nextParameter());
                    values.push(userData[field]);
                }
            }
            if (setFields.length > 0) {
                let setString = setFields.join(", ");
                values.push(user.id);
                let query = `update ${this.userTable} set ${setString} where ${this.idColumn} = ` + params.nextParameter();
                await dbClient.execute(query, values);
            }

            // update secrets
            if (secrets) {
                setFields = [];
                values = [];
                params = this.dbPool.parameters();
                for (let field in secretsData) {
                    if (secretsData[field] != undefined && field != "userid") {
                        setFields.push(field + "= " + params.nextParameter());
                        values.push(secretsData[field]);
                    }
                }
                if (setFields.length > 0) {
                    let setString = setFields.join(", ");
                    values.push(user.id);
                    let query = `update ${this.userSecretsTable} set ${setString} where userid = ` + params.nextParameter();
                    await dbClient.execute(query, values );
                }
    
            }

            await dbClient.commit();

        } catch (e) {
            await dbClient.rollback();
            throw e
        } finally {
            dbClient.release()
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
        if (secrets) secrets = {...secrets};
        if (secrets && !secrets.password) throw new CrossauthError(ErrorCode.PasswordFormat, "Password required when creating user");
        if (secrets && this.useridForeignKeyColumn in secrets) delete secrets[this.useridForeignKeyColumn];
        if (secrets && "userid" in secrets) delete secrets["userid"];

        const dbClient = await this.dbPool.connect();

        let userid : string|number|undefined;

        try {

            await dbClient.startTransaction();


            let userData = {...user};
            let secretsData = secrets? {...secrets} : undefined;
            if ("email" in userData && userData.email) {
                userData = {email_normalized: this.normalizeEmail ? DbUserStorage.normalize(userData.email) : userData.email, ...userData};
            }
            if ("username" in userData && userData.username) {
                userData = {username_normalized: this.normalizeUsername ? DbUserStorage.normalize(userData.username) : userData.username, ...userData};
            }

            // create user
            let fields : string[] = [];
            let placeholders: string[] = [];
            let values: any[] = [];
            const params = this.dbPool.parameters();
            //fields.push(this.idColumn);
            //placeholders.push("DEFAULT");

            for (let field in userData) {
                if (userData[field] != undefined && field != "id") {
                    fields.push(field);
                    placeholders.push(params.nextParameter());
                    values.push(userData[field]);
                }
            }
            if (fields.length > 0) {
                let fieldsString = fields.join(", ");
                let placeholdersString = placeholders.join(", ");
                const query = `insert into ${this.userTable} (${fieldsString}) values (${placeholdersString}) returning ${this.idColumn}`;
                const ret = await dbClient.execute(query, values);
                if (ret.length == 0 || !(ret[0][this.idColumn])) throw new CrossauthError(ErrorCode.Connection, "Couldn't create user");
                userid = ret[0][this.idColumn];
            }
            if (!userid) throw new CrossauthError(ErrorCode.Connection, "Couldn't create user");

            // create secrets
            if (secrets) {
                fields = [];
                placeholders = [];
                values = [];
                const params = this.dbPool.parameters();
                fields.push("userid");
                placeholders.push(params.nextParameter());
                values.push(userid);
                for (let field in secretsData) {
                    if (secretsData[field] != undefined && field != "userid") {
                        fields.push(field);
                        placeholders.push(params.nextParameter());
                        values.push(secretsData[field]);
                    }
                }
            
                if (fields.length > 0) {
                    let fieldsString = fields.join(", ");
                    let placeholdersString = placeholders.join(", ");
                    const query = `insert into ${this.userSecretsTable} (${fieldsString}) values (${placeholdersString})`;
                    CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
                    await dbClient.execute(query, values);
                }
    
            }

            await dbClient.commit();

            const userAndSecrets = await this.getUserById(userid);
            return userAndSecrets.user;

        } catch (e) {
            await dbClient.rollback();
            const ce = CrossauthError.asCrossauthError(e);
            CrossauthLogger.logger.debug(j({err: ce}));
            if (ce.code == ErrorCode.ConstraintViolation) {
                throw new CrossauthError(ErrorCode.UserExists, "User already exists");
            }
            throw ce;
        } finally {
            dbClient.release();
        }
    }

    async deleteUserByUsername(username : string) : Promise<void>  {
        const dbClient = await this.dbPool.connect();

        let {user} = await this.getUserByUsername(username);
        let userid = user.id;
        try {

            await dbClient.startTransaction();


            let params = this.dbPool.parameters();
            let query = `delete from ${this.userSecretsTable} where ${this.useridForeignKeyColumn}=` + params.nextParameter();
            await dbClient.execute(query, [userid]);
            params = this.dbPool.parameters();
            query = `delete from ${this.userTable} where username=` + params.nextParameter();
                await dbClient.execute(query, [username]);
    
            await dbClient.commit();

        } catch (e) {
            await dbClient.rollback();
            throw e
        } finally {
            dbClient.release()
        }
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
        const dbClient = await this.dbPool.connect();

        try {

            await dbClient.startTransaction();

            let params = this.dbPool.parameters();
            let query =  `delete from ${this.userSecretsTable} where ${this.useridForeignKeyColumn}=` + params.nextParameter();
            await dbClient.execute(query, [id]);
            params = this.dbPool.parameters();
            query =  `delete from ${this.userTable} where ${this.idColumn}=` + params.nextParameter();
            await dbClient.execute(query, [id]);
    
            await dbClient.commit();

        } catch (e) {
            await dbClient.rollback();
            throw e
        } finally {
            dbClient.release()
        }
    }
    
}

///////////////////////////////////////////////////////////////////////////
// KeyStorage

/**
 * Optional parameters for {@link DbKeyStorage}.
 * 
 * See {@link DbKeyStorage.constructor} for definitions.
 */
export interface DbKeyStorageOptions {
    keyTable? : string,
    useridForeignKeyColumn? : string;
}

/**
 * Implementation of {@link KeyStorage } where keys stored in a database managed by
 * a database engine.
 * 
 * This is an abstract class.  Instantiate a subclass instead, 
 * eg {@link PostgresKeyStorage}.
 * 
 * By default, table is called `key`.  It must have at least three fields:
 *    * `value string type unique`
 *    * `userid String type or integer`
 *    * `created timestamp`
 *    * `expires timestamp`
 * `key` must have `\@unique`.  It may also contain an ID column, which is not used.  If in the schema,
 * it must be autoincrement.  THe `userid` may be a `String` or `Int`.  If a database table is used for
 * user storage (eg {@link PostgresUserStorage} this should be a foreign key to the user table), in which case there
 * should also be a `user` field (see Prisma documentation on foreign keys).
 * 
 * In returned {@link @crossauth/common!Key} objects, userid is camelcase.  By 
 * default Postgres is case-insensitive.  If the columns is `userid` in lowercase,
 * it is converted to `userid` when returned.  Vice versa when saving to the database.
 */
export class DbKeyStorage extends KeyStorage {
    private keyTable : string = "keys";
    private dbPool : DbPool;
    private useridForeignKeyColumn = "userid";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param dbPool the instance of the Posrgres client. 
     * @param options See {@link PrismaKeyStorageOptions}
     */
    constructor(dbPool : DbPool, options : DbKeyStorageOptions = {}) {
        super();
        setParameter("transactionTimeout", ParamType.Number, this, options, "TRANSACTION_TIMEOUT");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");

        if (options.keyTable) {
            this.keyTable = options.keyTable;
        }
        this.dbPool = dbPool;
    }
    
    async getKey(key : string) : Promise<Key> {

        const dbClient = await this.dbPool.connect();

        try {

            await dbClient.startTransaction();

            const ret = await this.getKeyInTransaction(dbClient, key);

            await dbClient.commit();

            return ret;

        } catch (e) {
            await dbClient.rollback();
            throw e
        } finally {
            dbClient.release()
        }
    }

    private async getKeyInTransaction(
        dbClient : DbConnection,
        keyValue : string) : Promise<Key> {

        const params = this.dbPool.parameters();
        let query = `select * from ${this.keyTable} where value = ` + params.nextParameter();
        let res = await dbClient.execute(query, [keyValue]);
            if (res.length == 0) {
            throw new CrossauthError(ErrorCode.InvalidKey);
        }
        
        return this.makeKey(res[0]);
    }

    private makeKey(fields: {[key:string]:any}) : Key {
        fields = {...fields};
        let value : string;
        let userid : number|string|null = null;
        let created: Date;
        let expires: Date|undefined = undefined; 
        if (this.useridForeignKeyColumn in fields) {
            userid = fields[this.useridForeignKeyColumn];
            if (this.useridForeignKeyColumn != "userid") {
                delete fields[this.useridForeignKeyColumn];
            } 
        } 
        if (fields.value) value = fields.value;
        else throw new CrossauthError(ErrorCode.InvalidKey, "No value in key");
        if (fields.created) created = fields.created;
        else throw new CrossauthError(ErrorCode.InvalidKey, "No creation date in key");
        if (fields.expires) expires = fields.expires;

        if (!fields.userid) fields.userid;
        
        return {
            value,
            userid,
            created,
            expires,
            ...fields,
        }

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

        let fields : string[] = [this.useridForeignKeyColumn, "value", "created", "expires", "data"];
        let params = this.dbPool.parameters();
        let placeholders: string[] = []
        for (let i=0; i<5; ++i) {
            placeholders.push(params.nextParameter())
        }
        //let placeholders: string[] = ["$1", "$2", "$3", "$4", "$5"];
        let values: any[] = [userid ?? null, value, created, expires ?? null, data ?? ""];
        for (let field in extraFields) {
            fields.push(field);
            //placeholders.push("$"+i++);
            placeholders.push(params.nextParameter());
            values.push(extraFields[field]);
        }
        let fieldsString = fields.join(", ");
        let placeholdersString = placeholders.join(", ");
        const dbClient = await this.dbPool.connect();

        try {

            const query = `insert into ${this.keyTable} (${fieldsString}) values (${placeholdersString})`;
            await dbClient.execute(query, values);

        } catch (e) {
            const ce = CrossauthError.asCrossauthError(e);
            if (ce.code == ErrorCode.ConstraintViolation) {
                CrossauthLogger.logger.warn(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
                CrossauthLogger.logger.debug(j({err: e}));
                error = new CrossauthError(ErrorCode.KeyExists);
            } else {
                CrossauthLogger.logger.debug(j({err: e}));
                error = new CrossauthError(ErrorCode.Connection, "Error saving key");
            }
        } finally {
            dbClient.release()
        }
        if (error) {
            throw error;
        }
    }

    async deleteKey(value : string) : Promise<void>  {
        const dbClient = await this.dbPool.connect();

        try {
            let params = this.dbPool.parameters();
            let query = `delete from ${this.keyTable} where value=`;
            query += params.nextParameter();
            CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
            await dbClient.execute(query, [value]);
        } finally {
            dbClient.release();
        }
    }

    async deleteAllForUser(userid : string | number | undefined, prefix : string, except? : string) : Promise<void>  {
        const dbClient = await this.dbPool.connect();

        try {
            let query;
            let values : any[] = [];
            let exceptClause = "";
            let params = this.dbPool.parameters();
            if (userid) {
                const param1 = params.nextParameter();
                const param2 = params.nextParameter();
                query = `delete from ${this.keyTable} where ${this.useridForeignKeyColumn} = ${param1} and value like ${param2} `;
                values = [userid];
            } else {
                const param1 = params.nextParameter();
                query = `delete from ${this.keyTable} where ${this.useridForeignKeyColumn} is null and value like ${param1}`;
            }
            values.push(prefix+"%");
            if (except) {
                exceptClause = "and value != " + params.nextParameter();
                values.push(except);
            }
            query += " " + exceptClause;

            CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
            await dbClient.execute(query, values);
    

        } catch (e) {
            throw e
        } finally {
            dbClient.release()
        }
    }

    async deleteMatching(key : Partial<Key>) : Promise<void> {
        const dbClient = await this.dbPool.connect();

        try {
            let andClause : string[] = [];
            let values : any[] = [];
            const params = this.dbPool.parameters();
            for (let entry in key) {
                let column = entry == "userid" ? this.useridForeignKeyColumn : entry;
                let value = key[entry];
                if (value == null) {
                    andClause.push(column + " is null");
                } else {
                    andClause.push(column + " = " + params.nextParameter());
                    values.push(key[entry])    
                }
            }
            let andString = andClause.join(" and ");

            let query = `delete from ${this.keyTable} where ${andString}`;
            await dbClient.execute(query, values);
    
        } catch (e) {
            throw e
        } finally {
            dbClient.release()
        }
    }

    async deleteWithPrefix(userid : string | number | undefined, prefix : string) : Promise<void> {
        const dbClient = await this.dbPool.connect();

        try {
            let query : string;
            let values : any[] = [];
            const params = this.dbPool.parameters();
            if (userid) {
                let param1 = params.nextParameter();
                let param2 = params.nextParameter();
                query = `delete from ${this.keyTable} where ${this.useridForeignKeyColumn} = ${param1} and value like ${param2}`;
                values.push(userid);
            } else {
                let param1 = params.nextParameter();
                query = `delete from ${this.keyTable} where ${this.useridForeignKeyColumn} is null and value like ${param1}`;
            }
            values.push(prefix+"%")
            await dbClient.execute(query, values);
    

        } catch (e) {
            throw e
        } finally {
            dbClient.release()
        }
    }

    async getAllForUser(userid : string|number|undefined) : Promise<Key[]> {
        const dbClient = await this.dbPool.connect();

        try {

            let returnKeys : Key[] = [];
            let query : string;
            let values : any[] = [];
            const params = this.dbPool.parameters();
            if (userid) {
                query = `select * from ${this.keyTable} where ${this.useridForeignKeyColumn} = ` + params.nextParameter();
                values = [userid]
            } else {
                query = `select * from ${this.keyTable} where ${this.useridForeignKeyColumn} is null`;
            }
            CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
            let res = await dbClient.execute(query, values);
                if (res.length == 0) {
                return [];
            }
    
            for (let row of res) {
                let key : Key = this.makeKey(row);
                if (this.useridForeignKeyColumn != "userid") {
                    key["userid"] = key[this.useridForeignKeyColumn];
                    delete key[this.useridForeignKeyColumn];
                }
                returnKeys.push(key);
            }

            return returnKeys;

        } catch (e) {
            throw e
        } finally {
            dbClient.release()
        }
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param key the new values of the key.   `value` must be set and will not be updated.
     *        any other fields set (not undefined) will be updated.
     */
    async updateKey(key : Partial<Key>) : Promise<void> {
        const dbClient = await this.dbPool.connect();

        try {

            await dbClient.startTransaction();
            await this.updateKeyInTransaction(dbClient, key);
            await dbClient.commit();

        } catch (e) {
            await dbClient.rollback();
            throw e
        } finally {
            dbClient.release()
        }
    }
    
    private async updateKeyInTransaction(
        dbClient : DbConnection,
        key : Partial<Key>) : Promise<void> {

            let keyData = {...key};
            if (!(key.value)) throw new CrossauthError(ErrorCode.InvalidKey);
            delete keyData.value;

            // update key
            let setFields : string[] = [];
            let values: any[] = [];
            let params = this.dbPool.parameters();
            for (let field in keyData) {
                let dbField = field;
                if (keyData[field] != undefined && field == "userid" && this.useridForeignKeyColumn != "userid" ) {
                    dbField = this.useridForeignKeyColumn;
                }
                setFields.push(field + "= " + params.nextParameter());
                values.push(keyData[dbField]);
            }
            values.push(key.value);
            if (setFields.length > 0) {
                let setString = setFields.join(", ");
                let query = `update ${this.keyTable} set ${setString} where value = ` + params.nextParameter();
                CrossauthLogger.logger.debug(j({msg: "Executing query", query: query}));
                await dbClient.execute(query, values);
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
        async updateManyData(keyName : string, dataArray: {dataName: string, value: any | undefined}[]) : Promise<void> {
            const dbClient = await this.dbPool.connect();
    
            try {
    
                await dbClient.startTransaction();
    
                const key = await this.getKeyInTransaction(dbClient, keyName);
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
    
                await this.updateKeyInTransaction(dbClient, {value: key.value, data: JSON.stringify(data)});
                await dbClient.commit();
            } catch (e) {
                await dbClient.rollback();
    
                if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                    CrossauthLogger.logger.debug(j({err: e}));
                    throw new CrossauthError(ErrorCode.Connection, "Failed updating session data");
                }
                throw e;
            } finally {
                dbClient.release()
            }         
        }
    

    /**
     * See {@link KeyStorage}.
     */
    async deleteData(keyName : string, dataName: string) : Promise<void> {
        const dbClient = await this.dbPool.connect();

        try {

            await dbClient.startTransaction();

            const key = await this.getKeyInTransaction(dbClient, keyName);
            let data : {[key:string] : any} = {};
            let changed = false;
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
                await this.updateKeyInTransaction(dbClient, {value: key.value, data: JSON.stringify(data)});
            await dbClient.commit();
        } catch (e) {
            await dbClient.rollback();

            if (e && typeof e == "object" && !("isCrossauthError" in e)) {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Failed updating session data");
            }
            throw e;
        } finally {
            dbClient.release()
        }         
    }
}

///////////////////////////////////////////////////////////////////////////
// OAuthClientStorage

/**
 * Optional parameters for {@link PrismaOAuthClientStorage}.
 */
export interface DbOAuthClientStorageOptions extends OAuthClientStorageOptions {

    /** Table name of the OAuth Client table.  Default oauthclient */
    clientTable? : string,

    /** Table name of the OAuth Redirect Uri table.  Default oauthclientredirecturi */
    redirectUriTable? : string,

    /** Prisma name of the OAuth valid flows table.  Default oauthclientvalidflow */
    validFlowTable? : string,

    /** Name of the user id column in the client table.  
     * Default `userid`.
     */
    useridForeignKeyColumn? : string,
}

/**
 * Implementation of {@link OAuthClientStorage } where clients stored in a database managed by
 * the Prisma ORM.
 */
export class DbOAuthClientStorage extends OAuthClientStorage {
    private clientTable : string = "oauthclient";
    private redirectUriTable : string = "oauthclientredirecturi";
    private validFlowTable : string = "oauthclientvalidflow";
    private dbPool : DbPool;
    private useridForeignKeyColumn = "userid";

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(dbPool : DbPool, options : DbOAuthClientStorageOptions = {}) {
        super();
        setParameter("clientTable", ParamType.String, this, options, "OAUTH_CLIENT_TABLE");
        setParameter("redirectUriTable", ParamType.String, this, options, "OAUTH_REDIRECTURI_TABLE");
        setParameter("validFlowTable", ParamType.String, this, options, "OAUTH_VALID_FLOW_TABLE");
        setParameter("updateMode", ParamType.String, this, options, "OAUTHCLIENT_UPDATE_MODE");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        this.dbPool = dbPool;
    }

    async getClientById(client_id : string) : Promise<OAuthClient> {
        let dbClient = await this.dbPool.connect();
        try {
            await dbClient.startTransaction();
            const ret = await this.getClientWithTransaction(dbClient, "client_id", client_id, undefined);
            await dbClient.commit();
            if (ret.length == 0) throw new CrossauthError(ErrorCode.InvalidClientId);
            return ret[0];

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();

        }
    }

    async getClientByName(name : string, userid? : string|number|null) : Promise<OAuthClient[]> {
        let dbClient = await this.dbPool.connect();
        try {
            await dbClient.startTransaction();
            const ret = await this.getClientWithTransaction(dbClient, "client_name", name, userid);
            await dbClient.commit();
            if (ret.length == 0) throw new CrossauthError(ErrorCode.InvalidClientId);
            return ret;

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();

        }
    }

    private makeClient(fields : {[key:string]:any}) : OAuthClient {
        let client_id : string|undefined = undefined;
        let client_name : string|undefined = undefined;
        let client_secret : string|undefined = undefined;
        let confidential = false;
        let redirect_uri : string[] = [];
        let valid_flow : string[] = [];
        if ("client_id" in fields) client_id = fields["client_id"];
        if (!client_id) throw new CrossauthError(ErrorCode.InvalidClientId);
        if ("client_name" in fields) client_name = fields["client_name"];
        if (!client_name) throw new CrossauthError(ErrorCode.InvalidClientId);
        if ("client_secret" in fields) client_secret = fields["client_secret"];
        if ("confidential" in fields) confidential = fields["confidential"];
        if ("redirect_uri" in fields && fields["redirect_uri"]) redirect_uri = fields["redirect_uri"];
        if ("valid_flow" in fields && fields["valid_flow"]) valid_flow = fields["valid_flow"];
        return {
            client_id,
            client_name,
            client_secret,
            confidential,
            redirect_uri,
            valid_flow,
            ...fields,
        }
    }

    private async getClientWithTransaction(dbClient : DbConnection, field : string|undefined, value : string|undefined, userid : string|number|null|undefined, skip? : number, take? : number) : Promise<OAuthClient[]> {
        let clients : OAuthClient[] = [];

        // get clients
        let params = this.dbPool.parameters();
        let values : any[] = [];
        let query1 = `select c.*, r.uri as uri, null as flow from ${this.clientTable} as c left join ${this.redirectUriTable} r on c.client_id = r.client_id `;
        let where1 = "";
        if (field && value) {
            where1 = `where c.${field} = ` + params.nextParameter();
            values.push(value);
        }
        if (userid !== null && userid == undefined) {

        } else  {
            if (where1 == "") where1 = "where ";
            else where1 += " and ";
            if (userid == null) {
                where1 += "userid is null";
            } else {
                where1 += `${this.useridForeignKeyColumn} = ` + params.nextParameter();;
                values.push(userid);
            }
        }

        let query2 = `select c.*, null as uri, f.flow as flow from ${this.clientTable} as c left join ${this.validFlowTable} f on c.client_id = f.client_id `;
        let where2 = "";
        if (field && value) {
            where2 = `where c.${field} = ` + params.nextParameter();
            values.push(value);
        }
        if (userid !== null && userid == undefined) {

        } else  {
            if (where2 == "") where2 = "where ";
            else where2 += " and ";
            if (userid == null) {
                where2 += "userid is null";
            } else {
                where2 += `${this.useridForeignKeyColumn} = ` + params.nextParameter();;
                values.push(userid);
            }
        }

        if (take) {
            if (!skip) skip = 0;
            skip = Number(skip);
            take = Number(take);
            if (where1 == "") where1 = "where ";
            else where1 += " and ";
            where1 += ` c.client_id in (select client_id from ${this.clientTable} limit ${take} offset ${skip})`;
            if (where2 == "") where2 = "where ";
            else where2 += " and ";
            where2 += ` c.client_id in (select client_id from ${this.clientTable} limit ${take} offset ${skip})`;
        }

        query1 += where1;
        query2 += where2;

        let query = query1 + " union " + query2 + " order by client_id";
        const clientsRes = await dbClient.execute(query, values);
        let currentClient : OAuthClient | undefined = undefined;
        for (let client of clientsRes) {
            if (!currentClient || client.client_id != currentClient.client_id) {
                if (currentClient) clients.push(currentClient);
                currentClient = this.makeClient(client);
                currentClient.valid_flow = [];
                currentClient.redirect_uri = [];  
            }
            if (client.uri) currentClient.redirect_uri.push(client.uri);
            if (client.flow) currentClient.valid_flow.push(client.flow);
        }
        if (currentClient) clients.push(currentClient);

        return clients;
    }

    /**
     * Saves a key in the session table.
     * 
     * @param client fields for the client to create
     * @throws {@link @crossauth/common!CrossauthError } if the client could not be stored.
     */
    async createClient(client : OAuthClient) : Promise<OAuthClient> {
        let dbClient = await this.dbPool.connect();
        try {
            await dbClient.startTransaction();

            if (!client.client_id) throw new CrossauthError(ErrorCode.InvalidClientId);
            let res = await this.getClientWithTransaction(dbClient, "client_id", client.client_id, client.userid);
            if (res.length != 0) throw new CrossauthError(ErrorCode.ClientExists);
            let ret = await this.createClientWithTransaction(dbClient, client);

            await dbClient.commit();

            return ret;

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();
        }
    }

    private async createClientWithTransaction(dbClient : DbConnection, client : OAuthClient) : Promise<OAuthClient> {
        const {redirect_uri, valid_flow, userid, ...clientData} = client;
        if (userid) clientData[this.useridForeignKeyColumn] = userid;
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

        
        // create client (without redirect uri and valid flows) - may take seveal attempts to get a unique client_id
        let fields : string[] = [];
        let placeholders : string[] = [];
        let values : any[] = [];
        let params = this.dbPool.parameters();
        try {
            for (let field in clientData) {
                fields.push(field);
                placeholders.push(params.nextParameter());
                values.push(clientData[field]);
            }
            if (fields.length > 0) {
                let fieldsString = fields.join(", ");
                let placeholdersString = placeholders.join(", ");
                const query = `insert into ${this.clientTable} (${fieldsString}) values (${placeholdersString})`;
                await dbClient.execute(query, values);
            }
        } catch (e) {
            if (typeof(e) == "object" && e != null && "code" in e && typeof(e.code) == "string" && (e.code.startsWith("22") || e.code.startsWith("23"))) {

                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.InvalidClientId, "Attempt to create an OAuth client with a client_id that already exists. Maximum attempts failed");
            } else {
                CrossauthLogger.logger.debug(j({err: e}));
                throw new CrossauthError(ErrorCode.Connection, "Error saving OAuth client");
            }
        }
        let res = await this.getClientWithTransaction(dbClient, "client_id", client.client_id, client.userid);

        if (res.length == 0) {
            CrossauthLogger.logger.error(j({msg: "Attempt to create key that already exists. Stack trace follows"}));
            throw new CrossauthError(ErrorCode.KeyExists);    
        }
        let newClient = res[0];

        // create redirect uris
        if (redirect_uri) {
                for (let i=0; i<redirect_uri.length; ++i) {
                    values = [];
                    params = this.dbPool.parameters();
                    let query = `insert into ${this.redirectUriTable} (client_id, uri) values (` + params.nextParameter() + ", " + params.nextParameter() + ")";
                    values.push(newClient.client_id);
                    values.push(redirect_uri[i]);
                    await dbClient.execute(query, values);
                }
        }

        // create valid flows
        if (valid_flow) {
            for (let i=0; i<valid_flow.length; ++i) {
                values = [];
                params = this.dbPool.parameters();
                let query = `insert into ${this.validFlowTable} (client_id, flow) values (` + params.nextParameter() + ", " + params.nextParameter() + ")";
                values.push(newClient.client_id);
                values.push(valid_flow[i]);
                await dbClient.execute(query, values);
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
        let dbClient = await this.dbPool.connect();
        try {
            await dbClient.startTransaction();

            const res = this.deleteClientWithTransaction(dbClient, client_id);

            await dbClient.commit();

            return res;

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();
        }
    }


    private async deleteClientWithTransaction(dbClient : DbConnection, client_id : string) : Promise<void> {

        let values : any[] = [];
        let params = this.dbPool.parameters();
        let param = params.nextParameter();
        let query = `delete from ${this.redirectUriTable} where client_id = ${param}`;
        values.push(client_id);
        await dbClient.execute(query, values);

        query = `delete from ${this.validFlowTable} where client_id = ${param}`;
        await dbClient.execute(query, values);

        query = `delete from ${this.clientTable} where client_id = ${param}`;
        await dbClient.execute(query, values);
    }

    /**
     * If the given session key exist in the database, update it with the passed values.  If it doesn't
     * exist, throw a CreossauthError with InvalidKey.
     * @param client the client to update.  It will be searched on its client_id, which cannot be updated.
     */
    async updateClient(client : Partial<OAuthClient>) : Promise<void> {
        let dbClient = await this.dbPool.connect();
        try {
            await dbClient.startTransaction();

            const res = this.updateClientWithTransaction(dbClient, client);

            await dbClient.commit();

            return res;

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();
        }
    }

    // This gives a Rust error when used with a transaction on SQLlite

    private async updateClientWithTransaction(dbClient : DbConnection, client : Partial<OAuthClient>) : Promise<void> {
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

        if (!client.client_id) throw new CrossauthError(ErrorCode.InvalidClientId, "No client ig given");
        let {client_id, redirect_uri, valid_flow, ...clientData} = client;
        if (!redirect_uri) redirect_uri = [];
        if (!valid_flow) valid_flow = [];

        // delete redirect URIs
        let params = this.dbPool.parameters();
        let query = `delete from ${this.redirectUriTable} where client_id = ` + params.nextParameter();
        await dbClient.execute(query, [client.client_id]);

        // delete valid flows
        params = this.dbPool.parameters();
        query = `delete from ${this.validFlowTable} where client_id = ` + params.nextParameter();
        await dbClient.execute(query, [client.client_id]);

        // update client
        let fields : string[] = [];
        let placeholders : string[] = [];
        let values : any[] = [];
        params = this.dbPool.parameters();
        query = `delete from ${this.validFlowTable} where client_id = ` + params.nextParameter();
        for (let field in clientData) {
            fields.push(field);
            placeholders.push(params.nextParameter());
            values.push(clientData[field])
        };
        if (fields.length > 0) {
            let fieldsString = fields.join(", ");
            let placeholdersString = placeholders.join(", ");
            query = `update ${this.clientTable} set (${fieldsString}) values (${placeholdersString})`;
            await dbClient.execute(query, values);
        }

        // create redirect uris
        if (redirect_uri) {
            for (let i=0; i<redirect_uri.length; ++i) {
                values = [];
                params = this.dbPool.parameters();
                let query = `insert into ${this.redirectUriTable} (client_id, uri) values (` + params.nextParameter() + ", " + params.nextParameter() + ")";
                values.push(client.client_id);
                values.push(redirect_uri[i]);
                await dbClient.execute(query, values);
            }
        }

        // create valid flows
        if (valid_flow) {
            for (let i=0; i<valid_flow.length; ++i) {
                values = [];
                params = this.dbPool.parameters();
                let query = `insert into ${this.validFlowTable} (client_id, flow) values (` + params.nextParameter() + ", " + params.nextParameter() + ")";
                values.push(client.client_id);
                values.push(valid_flow[i]);
                await dbClient.execute(query, values);
            }
        }

    }

    async getClients(skip? : number, take? : number, userid? : string|number|null) : Promise<OAuthClient[]> {

        let dbClient = await this.dbPool.connect();
        try {

            await dbClient.startTransaction();

            const res = this.getClientWithTransaction(dbClient, undefined, undefined, userid, skip, take);
            await dbClient.commit();
            return res;

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();
        }        
    }
}


///////////////////////////////////////////////////////////////////////////
// OAuthAuthorizationStorage

/**
 * Optional parameters for {@link DbOAuthAuthorizationStorage}.
 */
export interface DbOAuthAuthorizationStorageOptions extends OAuthClientStorageOptions {

    /** Prisma name of the OAuth Authorization table.  Default oAuthAuthorization */
    authorizationTable? : string,

    useridForeignKeyColumn? : string,

}

/**
 * Implementation of {@link OAuthAuthorizationStorage } where authorizations are stored in a database.
 */
export class DbOAuthAuthorizationStorage extends OAuthAuthorizationStorage {
    private authorizationTable : string = "oauthauthorization";
    private useridForeignKeyColumn = "userid"
    private dbPool : DbPool;

    /**
     * Constructor with user storage object to use plus optional parameters.
     * 
     * @param options See {@link PrismaOAuthClientStorageOptions}
     */
    constructor(dbPool : DbPool, options : DbOAuthClientStorageOptions = {}) {
        super();
        setParameter("authorizationTable", ParamType.String, this, options, "OAUTH_CLIENT_TABLE");
        setParameter("useridForeignKeyColumn", ParamType.String, this, options, "USER_ID_FOREIGN_KEY_COLUMN");
        this.dbPool = dbPool;
    }

    async getAuthorizations(client_id : string, userid : string|number|undefined) : Promise<(string|null)[]> {
        let dbClient = await this.dbPool.connect();
        try {

            const params = this.dbPool.parameters();
            const values : any[] = [];
            let query = `select scope from ${this.authorizationTable} where client_id = ` + params.nextParameter();
            values.push(client_id);
            if (userid === null) {
                query += ` and ${this.useridForeignKeyColumn} is null` 
            } else if (userid) {
                query += ` and ${this.useridForeignKeyColumn} = ` + params.nextParameter();
                values.push(userid);

            }
            const res = await dbClient.execute(query, values);
            const ret = res.map((r) => r.scope)
            return ret;

        } catch (e) {
            throw e;
        } finally {
            dbClient.release();
        }        
    }

    async updateAuthorizations(client_id : string, userid : string|number|null, scopes : string[]) : Promise<void> {
        let dbClient = await this.dbPool.connect();
        try {

            await dbClient.startTransaction();

            // delete authorizations
            let params = this.dbPool.parameters();
            let values : any[] = [];
            let query = `delete from ${this.authorizationTable} where client_id = ` + params.nextParameter();
            values.push(client_id);
            if (!userid) {
                query += ` and ${this.useridForeignKeyColumn} is null` 
            } else {
                query += ` and ${this.useridForeignKeyColumn} = ` + params.nextParameter();
                values.push(userid);

            }
            await dbClient.execute(query, values);

            // create authorizations
            for (let scope of scopes) {
                params = this.dbPool.parameters();
                values = [];
                query = `insert into ${this.authorizationTable} (client_id, userid, scope) values (` + params.nextParameter() + ", " + params.nextParameter() + ", " + params.nextParameter() + ")";
                values.push(client_id);
                values.push(userid);
                values.push(scope);
                await dbClient.execute(query, values);
    
            }

            await dbClient.commit();

        } catch (e) {
            await dbClient.rollback();
            throw e;
        } finally {
            dbClient.release();
        }        
    }
}
