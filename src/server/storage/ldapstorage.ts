import { UserStorage, UserStorageGetOptions, UserStorageOptions } from '../storage';
import { PrismaUserStorage } from './prismastorage';
import { User, UserSecrets, UserInputFields, UserSecretsInputFields } from '../../interfaces';
import { CrossauthError, ErrorCode } from '../../error';
import { CrossauthLogger, j } from '../..';
import { setParameter, ParamType } from '../utils';
import ldap from 'ldapjs';

/**
 * Optional parameters for {@link PrismaUserStorage}.
 * 
 * See {@link PrismaUserStorage.constructor} for definitions.
 */
export interface LdapStorageOptions {

    /** Utl running LDAP server. eg ldap://ldap.example.com or ldap://ldap,example.com:636 
     *  No default (required)
     */
    ldapUrls? : string,

    /** Search base, for user queries, eg "dc=example,dc=com".  Default empty */
    ldapUserSearchBase? : string,

    /** Username attribute.  Default "cn".
     */
    ldapUsernameAttribute? : string,  

    /** Defaults to "(objectclass=*)" */
    ldapSearchFilter? : string;

}

export class LdapStorage extends UserStorage {
    private localStorage : UserStorage;
    private ldapUrls = [];
    private ldapUserSearchBase  = "";
    private ldapUsernameAttribute = "cn";

    constructor(localStorage : UserStorage, options : UserStorageOptions = {}) {
        super(options);
        this.localStorage = localStorage;
        setParameter("ldapUrls", ParamType.StringArray, this, options, "LDAP_URL", true);
        setParameter("ldapUserSearchBase", ParamType.String, this, options, "LDAP_USER_SEARCH_BASE");
        setParameter("ldapUsernameAttribute", ParamType.String, this, options, "LDAP_USENAME_ATTRIBUTE");
          
    }

    /**
     * If you enable signup, you will need to implement this method
     */
    async createUser(user : UserInputFields, secrets : UserSecretsInputFields) 
        : Promise<User> {

        if (!secrets.password) throw new CrossauthError(ErrorCode.PasswordInvalid);
        const ldapUser = await this.getLdapUser(user.username, secrets.password);
        return await super.createUser(ldapUser, {});
    }

    async getUserByUsername(
        username : string, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.localStorage.getUserByUsername(username, options);
         }

    async getUserById(
        id : string|number, 
         options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.localStorage.getUserById(id, options);
         }

    async getUserByEmail(
        email : string | number, 
        options? : UserStorageGetOptions) : Promise<{user: User, secrets: UserSecrets}> {
            return await this.getUserByEmail(email, options);
        }

    async updateUser(user : Partial<User>, _secrets? : Partial<UserSecrets>) : Promise<void> {
        return await this.localStorage.updateUser(user, undefined);
    }

    /**
     * If your storage supports this, delete the named user from storage.
     * @param username username to delete
     */
    async deleteUserByUsername(username : string) : Promise<void> {
        await this.localStorage.deleteUserByUsername(username);
    }

    async getLdapUser(username : string, password : string) : Promise<User> {
        let ldapClient : ldap.Client;
        try {
            const sanitizedUsername = LdapStorage.sanitizeLdapDn(username);
            const bindDn = [this.ldapUsernameAttribute+"="+sanitizedUsername, this.ldapUserSearchBase].join(",");
            if (!password) throw new CrossauthError(ErrorCode.PasswordInvalid);
            ldapClient = await this.ldapBind(bindDn, password);
            return await this.searchUser(ldapClient, bindDn);
              
        } catch (e) {
            CrossauthLogger.logger.error(j({err: e}));
            if (e instanceof CrossauthError) throw e;
            throw new CrossauthError(ErrorCode.UsernameOrPasswordInvalid);
        }
    }

    // bind and return the ldap client
    // from https://github.com/shaozi/ldap-authentication/blob/master/index.js
    private ldapBind(dn : string, password : string) : Promise<ldap.Client> {
        return new Promise((resolve, reject) => {
            let client = ldap.createClient({url: this.ldapUrls});
        
            client.on('connect', function () {
                client.bind(dn, password, function (err) {
                    if (err) {
                    reject(err)
                    client.unbind()
                    return
                    }
                    resolve(client)
                })
            });
            //Fix for issue https://github.com/shaozi/ldap-authentication/issues/13
            client.on('timeout', (err) => {
                reject(err)
            });
            client.on('connectTimeout', (err) => {
                reject(err)
            });
            client.on('error', (err) => {
                reject(err)
            });
        
            client.on('connectError', function (error) {
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
      ) : Promise<User> {
        return new Promise(function (resolve, reject) {
            let searchOpts : {[key:string]: any} = {
                scope: 'base',
            }
            if (attributes) searchOpts.attributes = attributes;
            ldapClient.search(userDn, searchOpts, 
                function (err : any, res : any) {
                    let user : User|undefined = undefined;
                    if (err) {
                        reject(err)
                        ldapClient.unbind()
                        return
                    }
                    res.on('searchEntry', function (entry: any) {
                        user = LdapStorage.searchResultToUser(entry.pojo)
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
          
    private static searchResultToUser(pojo : {[key:string]:any}) : User {
        let user : User = { id: pojo.objectName, username: pojo.objectName, state: "active" }
        pojo.attributes.forEach((attribute : {type: string, values: any[]}) => {
            user[attribute.type] =
            attribute.values.length == 1 ? attribute.values[0] : attribute.values
        })
        return user
    }
      
    static sanitizeLdapDn(dn : string) : string {
        return dn.replace("\\", "\\\\")
                 .replace(",", "\\,")
                 .replace("+", "\\+")
                 .replace('"', '\\"')
                 .replace("<", "\\<")
                 .replace(">", "\\>")
                 .replace("#", "\\#")
                 .trim()
    }

    static sanitizeLdapDnForSerach(dn : string) : string {
        return LdapStorage.sanitizeLdapDn(dn)
                 .replace("*", "\\*")
                 .replace("(", "\\(")
                 .replace(")", "\\)");
    }
};
