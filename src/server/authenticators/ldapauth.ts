import type { User, UserSecretsInputFields, Key, UserInputFields } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '../../error.ts';
import { UserStorage } from '../storage.ts'
import { CrossauthLogger, j } from '../../logger.ts';
import { setParameter, ParamType } from '../utils.ts';
import { Authenticator, type AuthenticationParameters , type AuthenticationOptions} from '../auth.ts';
import { LdapStorage } from '../storage/ldapstorage.ts';

/** Optional parameters to pass to {@link LdapAuthenticator} constructor. */
export interface LdapAuthenticatorOptions extends AuthenticationOptions {
    ldapAutoCreateAccount? : boolean,
}

/**
 * Does username/password authentication using PBKDF2 hashed passwords.
 */
export class LdapAuthenticator extends Authenticator {

    private ldapAutoCreateAccount : boolean = false;
    private ldapStorage : LdapStorage;

    /**
     * Create a new authenticator.
     * 
     * See crypto.pbkdf2 for more information on the optional parameters.
     * 
     * @param userStorage an object that can getch usernames and hashed passwords from wherever they are stored, eg a database table
     * @param iterations number of PBKDF2 iterations.  Defaults to 10000.
     * @param keyLen length of generated hash.  Defaults to 64.
     * @param digest digest algorithm to use.  Defaults to `sha512`.
     * @param saltLength generate a salt with this number of characters.  Defaults to 16.
     */
    constructor(ldapStorage : LdapStorage,
                options : LdapAuthenticatorOptions = {}) {
        super({friendlyName: "LDAP", ...options});
        setParameter("ldapAutoCreateAccount", ParamType.Boolean, this, options, "LDAP_AUTO_CREATE_ACCOUNT");
        this.ldapStorage = ldapStorage;
    }

    /**
     * Authenticates the user, returning a the user as a {@link User} object.
     * 
     * If you set `extraFields` when constructing the {@link UserStorage} instance passed to the constructor,
     * these will be included in the returned User object.  `hashedPassword`, if present in the User object,
     * will be removed.
     * 
     * @param username the username to authenticate
     * @param password the password to hash and match against the hashed password on the user storage.
     * @returns A {@link User } object with the optional extra fields but without the hashed password.  See explaination above.
     * @throws {@link index!CrossauthError} with {@link ErrorCode} of `Connection`, `UserNotExist`or `PasswordNotMatch`.
     */
    async authenticateUser(user : UserInputFields, _secrets: UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (!params.password) throw new CrossauthError(ErrorCode.PasswordInvalid, "Password not provided");
        await this.ldapStorage.getLdapUser(user.username, params.password);
        let localUser : User;
        if (this.ldapAutoCreateAccount) {
            try {
                const resp = await this.ldapStorage.getUserByUsername(user.username);
                localUser = resp.user;
            } catch (e) {
                localUser = await this.ldapStorage.createUser(user, params);
            }
        } else {
            const resp = await this.ldapStorage.getUserByUsername(user.username);
            localUser = resp.user;
        }
        if (localUser.state == "awaitingtwofactorsetup") throw new CrossauthError(ErrorCode.TwoFactorIncomplete);
        if (localUser.state == "awaitingemailverification") throw new CrossauthError(ErrorCode.EmailNotVerified);
        if (localUser.state == "deactivated") throw new CrossauthError(ErrorCode.UserNotActive);
    }

    secretNames() : string[] {
        return ["password"];
    }

    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    async createPersistentSecrets(_username : string, params: AuthenticationParameters, repeatParams: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        if (!params.password) throw new CrossauthError(ErrorCode.Unauthorized, "No password provided");
        if (repeatParams && repeatParams.password != params.password) {
            throw new CrossauthError(ErrorCode.PasswordMatch);
        }
        return {};
    }

    async createOneTimeSecrets(_user : User) : Promise<Partial<UserSecretsInputFields>> {
        return { }
    }

    canCreateUser() : boolean { return true; }
    canUpdateUser() : boolean { return true; }

    skipEmailVerificationOnSignup() : boolean {
        return false;
    }
    async prepareConfiguration(_user : UserInputFields) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {
        return undefined;
    }

    async reprepareConfiguration(_username : string, _sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>, newSessionData: {[key:string]: any}|undefined}|undefined> {
        return undefined;
    }
}
