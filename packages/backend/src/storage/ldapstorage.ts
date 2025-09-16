// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { UserStorage, type UserStorageGetOptions, type UserStorageOptions } from '../storage';
import { type User, type UserSecrets, type UserInputFields, type UserSecretsInputFields } from '@crossauth/common';
import { CrossauthError, ErrorCode } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import { setParameter, ParamType } from '../utils';
import ldap from '@mbakereth/ldapjs';
//import LdapClient from 'ldapjs-client';
//import ldap from 'ldapauth-fork';

/**
 * A user returned by an LDAP server
 */
export interface LdapUser {

    /** The user's dn in LDAP */
    dn: string,

    /** Optional additional fields from LDAP */
    [ key : string ] : string|string[],
}

/**
 * Optional parameters for {@link LdapUserStorage}.
 */
export interface LdapUserStorageOptions extends UserStorageOptions {

    /** Utl running LDAP server. eg ldap://ldap.example.com or ldaps://ldap,example.com:1636 
     *  No default (required)
     */
    ldapUrls? : string[],

    /** Search base, for user queries, eg  `ou=users,dc=example,dc=com`.  Default empty */
    ldapUserSearchBase? : string,

    /** Username attribute for searches.  Default "cn".
     */
    ldapUsernameAttribute? : string,  

    /** A function to create a user object given the entry in LDAP and additional fields.
     * The additional fields might be useful for attributes that aren't in LDAP and the
     * user needs to be prompted for, for example email address.
     * The default function sets `username` to `uid` from `ldapUser`,
     * `state` to `active` and takes every field for `user` (overriding `status`
     * and `username` if present).
     */
    createUserFn?:  (user: Partial<User>, ldapUser: LdapUser) => UserInputFields;
}

function defaultCreateUserDn(user: Partial<User>, ldapUser: LdapUser) : UserInputFields {
    
    const uid = Array.isArray(ldapUser.uid) ? ldapUser.uid[0] : ldapUser.uid;
    return {username: uid, state: "active", ...user};
}

/**
 * Wraps another user storage but with the authentication done in LDAP.
 * 
 * This class still needs a user to be created in another database, with 
 * for example a user id that can be referenced in key storage, and a state
 * variable.
 * 
 * An admin account is not used.  Searches are done as the user, with the user's
 * password.
 */
export class LdapUserStorage extends UserStorage {
    private localStorage : UserStorage;
    private ldapUrls = [];
    private ldapUserSearchBase  = "";
    private ldapUsernameAttribute = "cn";
    private createUserFn:  (user: Partial<User>, ldapUser: LdapUser) => UserInputFields = defaultCreateUserDn;

    /**
     * Constructor.
     * @param localStorage the underlying storage where users are kept (without passwords)
     * @param options see {@link LdapUserStorageOptions}
     */
    constructor(localStorage : UserStorage, options : LdapUserStorageOptions = {}) {
        super(options);
        this.localStorage = localStorage;
        setParameter("ldapUrls", ParamType.JsonArray, this, options, "LDAP_URL", true);
        setParameter("ldapUserSearchBase", ParamType.String, this, options, "LDAP_USER_SEARCH_BASE");
        setParameter("ldapUsernameAttribute", ParamType.String, this, options, "LDAP_USENAME_ATTRIBUTE");
        if (options.createUserFn) this.createUserFn = options.createUserFn;
    }

    /**
     * Authenticates the user in LDAP and, if valid, creates a user in local
     * storage.
     * 
     * @param user passed to the default `createUserFn` to create the user object.  `username` field is used for LDAP authentication
     * @param secrets `password` for LDAP expected to be set here.
     * @returns the created user object, as it appears in local storage
     */
    async createUser(user : UserInputFields, secrets? : UserSecretsInputFields) 
        : Promise<User> {

        if (!secrets?.password) throw new CrossauthError(ErrorCode.PasswordInvalid);
        const ldapUser = await this.getLdapUser(user.username, secrets.password);
        user = this.createUserFn(user, ldapUser);
        return await this.localStorage.createUser(user, {password: "pbkdf2:sha256:32:600000:0:DISABLED:DISABLED"});
    }

    /**
     * Gets a user from the local storage.  Does not check LDAP.
     * @param username the username to fetch
     * @param options passed to `localStorage`'s `getUserByUsername()`
     * @returns the user
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `UsernameOrPasswordInvalid` or `Connection`
     */
    async getUserByUsername(
        username : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.localStorage.getUserByUsername(username, options);
         }

    /**
     * Gets a user from the local storage.  Does not check LDAP.
     * @param id the user id to fetch
     * @param options passed to `localStorage`'s `getUserByUsername()`
     * @returns the user
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `UsernameOrPasswordInvalid` or `Connection`
     */
    async getUserById(
        id : string|number, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.localStorage.getUserById(id, options);
         }

    /**
     * Gets a user from the local storage.  Does not check LDAP.
     * @param email the email address to fetch user by
     * @param options passed to `localStorage`'s `getUserByUsername()`
     * @returns the user
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `UsernameOrPasswordInvalid` or `Connection`
     */
    async getUserByEmail(
        email : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.localStorage.getUserByEmail(email, options);
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
            return await this.localStorage.getUserBy(field, value, options);
    }

    async getUsers(skip? : number, take? : number) : Promise<User[]> {
        return await this.localStorage.getUsers(skip, take);
    }

    /**
     * Updates a user in local storage.  Does not do an LDAP update.
     * @param user new fields for the user, plus `id` to match the user by
     * @param _secrets ignored as secrets cannot be updated
     * @returns 
     */
    async updateUser(user : Partial<User>, _secrets? : Partial<UserSecrets>) : Promise<void> {
        return await this.localStorage.updateUser(user, undefined);
    }

    /**
     * Deletes a user from local storage (not from LDAP)
     * @param username username to delete
     */
    async deleteUserByUsername(username : string) : Promise<void> {
        await this.localStorage.deleteUserByUsername(username);
    }

    /**
     * Deletes a user from local storage (not from LDAP)
     * @param id ID of the user to delete
     */
    async deleteUserById(id : string|number) : Promise<void> {
        await this.localStorage.deleteUserById(id);
    }

    /**
     * Gets the user from LDAP.  Does not check local storage.
     * 
     * If the user doesn't exist or authentication fails, an exception is thrown
     * @param username the username to fetch
     * @param password the LDAP password
     * @returns the matching {@link LdapUser}
     * @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} `UsernameOrPasswordInvalid` or `Connection`
     */
    async getLdapUser(username : string, password : string) : Promise<LdapUser> {
        let ldapClient : ldap.Client;
        try {
            const sanitizedUsername = LdapUserStorage.sanitizeLdapDnForSearch(username);
            const userDn = [this.ldapUsernameAttribute+"="+sanitizedUsername, this.ldapUserSearchBase].join(",");
            if (!password) throw new CrossauthError(ErrorCode.PasswordInvalid);
            CrossauthLogger.logger.debug(j({msg: "LDAP search "+userDn}));
            ldapClient = await this.ldapBind(userDn, password);
            return await this.searchUser(ldapClient, userDn);
              
        } catch (e) {
            CrossauthLogger.logger.debug(j({err: e}));
            const ce = CrossauthError.asCrossauthError(e);
            if (e instanceof ldap.InvalidCredentialsError) {
                throw new CrossauthError(ErrorCode.UsernameOrPasswordInvalid);
            } else if (ce.code != ErrorCode.UnknownError) {
                throw ce;
            } else {
                throw new CrossauthError(ErrorCode.Connection, "LDAP error getting user");            
            }
        }
    }

    // bind and return the ldap client
    // from https://github.com/shaozi/ldap-authentication/blob/master/index.js
    private ldapBind(dn : string, password : string) : Promise<ldap.Client> {
        return new Promise((resolve, reject) => {
            let client = ldap.createClient({url: this.ldapUrls});
        
            client.on('connect', function () {
                client.bind(dn, password, function (err : any) {
                    if (err) {
                    reject(err)
                    client.unbind()
                    return
                    }
                    resolve(client)
                })
            });
            //Fix for issue https://github.com/shaozi/ldap-authentication/issues/13
            client.on('timeout', (err : any) => {
                reject(err)
            });
            client.on('connectTimeout', (err : any) => {
                reject(err)
            });
            client.on('error', (err : any) => {
                reject(err)
            });
        
            client.on('connectError', function (error : any) {
                if (error) {
                    reject(error)
                    return
                }
            });
        });
    }

    private async searchUser(
        ldapClient : ldap.Client,
        userDn : string,
        attributes? : string[]
      ) : Promise<LdapUser> {
        return new Promise(function (resolve, reject) {
            let searchOpts : {[key:string]: any} = {
                scope: 'base',
            }
            if (attributes) searchOpts.attributes = attributes;
            ldapClient.search(userDn, searchOpts, 
                function (err : any, res : any) {
                    let user : LdapUser|undefined = undefined;
                    if (err) {
                        reject(err)
                        ldapClient.unbind()
                        return
                    }
                    res.on('searchEntry', function (entry: any) {
                        user = LdapUserStorage.searchResultToUser(entry.pojo)
                    })
                    res.on('error', function (err : any) {
                        reject(err)
                        ldapClient.unbind()
                    })
                    res.on('end', function (result : any) {
                    if (result.status != 0) {
                        reject(new CrossauthError(ErrorCode.Connection, "LDAP  onnection failed"));
                    } else if (user) {
                        resolve(user)
                    } else {
                        reject(new CrossauthError(ErrorCode.UsernameOrPasswordInvalid));
                    }
                    ldapClient.unbind()
                })
            })
        })
    }
          
    private static searchResultToUser(pojo : {[key:string]:any}) : LdapUser {
        let user : LdapUser = { dn: pojo.objectName, state: "active" }
        pojo.attributes.forEach((attribute : {type: string, values: any[]}) => {
            user[attribute.type] =
            attribute.values.length == 1 ? attribute.values[0] : attribute.values
        })
        return user
    }
      
    /**
     * Sanitises an LDAP dn for passing to bind (escaping special characters)
     * @param dn the dn to sanitise
     * @returns a sanitized dn
     */
    static sanitizeLdapDn(dn : string) : string {
        return dn.replace("\\", "\\\\")
                 .replace(",", "\,")
                 .replace("+", "\+")
                 .replace('"', '\"')
                 .replace("<", "\<")
                 .replace(">", "\>")
                 .replace("#", "\#")
                 .trim()
    }

    /**
     * Sanitises an LDAP dn for passing to searches (escaping special characters)
     * @param dn the dn to sanitise
     * @returns a sanitized dn
     */
    static sanitizeLdapDnForSearch(dn : string) : string {
        return LdapUserStorage.sanitizeLdapDn(dn)
                 .replace("*", "\*")
                 .replace("(", "\(")
                 .replace(")", "\)");
    }
};
