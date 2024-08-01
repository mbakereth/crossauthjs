import QRCode from 'qrcode';
import { authenticator as gAuthenticator } from 'otplib';
import type {
    User,
    Key,
    UserSecretsInputFields,
    UserInputFields } from '@crossauth/common';
//import { getJsonData } from '@crossauth/common';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { CrossauthLogger, j } from '@crossauth/common';
import {
    Authenticator,
    type AuthenticationParameters,
    type AuthenticationOptions } from '../auth.ts';
import { KeyStorage } from '../storage.ts';

/**
 * Authenticator for Time-Based One-Time Passwords (TOTP), eg 
 * Google Authenticator
 */
export class TotpAuthenticator extends Authenticator {

    private appName : string;

    /**
     * Constructor
     * @param appName this forms part of the QR code that users scan into 
     *                their authenticator app.  The name will appear in their app
     * @param options See {@link AuthenticationOptions}.
     */
    constructor(appName : string, options? : AuthenticationOptions) {
        super({friendlyName : "Google Authenticator", ...options});
        this.appName = appName;
    }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaType() : "none" | "oob" | "otp" { return "otp"; }

    /**
     * Used by the OAuth password_mfa grant type.
     */
    mfaChannel() : "none" | "email" | "sms" { return "none"; }

    private async createSecret(username : string, secret? : string) : 
        Promise<{qrUrl : string, secret: string}> {
        if (!secret) secret = gAuthenticator.generateSecret();
        let qrUrl = "";
        await QRCode.toDataURL(gAuthenticator.keyuri(username, this.appName, secret))
            .then((url) => {
                    qrUrl = url;
            })
            .catch((err) => {
                CrossauthLogger.logger.debug(j({err: err}));
                throw new CrossauthError(ErrorCode.UnknownError, 
                    "Couldn't generate 2FA URL");
            });

        return { qrUrl, secret };   
    }

    private async getSecretFromSession(
        username : string, 
        sessionKey : Key) : 
        Promise<{qrUrl: string, secret: string, factor2: string}> {
        const data = KeyStorage.decodeData(sessionKey.data);
        //const data = getJsonData(sessionKey);
        if (!("totpSecret" in data)) {
            throw new CrossauthError(ErrorCode.Unauthorized, 
                "TOTP data not in session");
        }
        if (!("factor2" in data)) {
            throw new CrossauthError(ErrorCode.Unauthorized, 
                "TOTP factor name not in session");
        }
        const savedSecret = data.totpSecret;
        const { qrUrl, secret } = 
            await this.createSecret(username, savedSecret);

        return {qrUrl, secret, factor2: data.factor2}
        
    }

    /**
     * Creates a shared secret and returns it, along with image data for the QR
     * code to display.
     * @param user the `username` is expected to be present.  All other fields 
     *             are ignored.
     * @returns `userData` containing `username`, `totpSecret`, `factor2` and 
     *          `qr`.
     *          `sessionData` containing the same except `qr`.
     */
    async prepareConfiguration(user : UserInputFields) : 
        Promise<{
            userData: { [key: string]: any },
            sessionData: { [key: string]: any }
            }|undefined> {

        if (!this.factorName) throw new CrossauthError(ErrorCode.Configuration,
            "Please set factorName on TotpAuthenticator before using");
            
        const { qrUrl, secret } = await this.createSecret(user.username);

        const userData = {
            username: user.username,
            qr: qrUrl,
            totpSecret: secret,
            factor2: this.factorName
        };
        const sessionData = {
            username: user.username,
            totpSecret: secret,
            factor2: this.factorName
        }
        return { userData, sessionData};
    }

    /**
     * For cases when the 2FA page was closed without completing.  Returns the 
     * same data as `prepareConfiguration`, without generating a new secret.
     * @param username user to return this for
     * @param sessionKey the session key, which should cantain the 
     *                   `sessionData` from `prepareConfiguration`, 
     * @returns `userData` containing `totpSecret`, `factor2` and `qr`.
     *          `secrets` containing `totpSecret`.
     *          `newSessionData` containing the same except `qr`.
     */
    async reprepareConfiguration(username : string, sessionKey : Key) : 
        Promise<{
            userData: { [key: string]: any },
            secrets: Partial<UserSecretsInputFields>,
            newSessionData: { [key: string]: any } | undefined
            }|undefined> {
        const { qrUrl, secret, factor2 } =
            await this.getSecretFromSession(username, sessionKey);
        return {
            userData: { qr: qrUrl, totpSecret: secret, factor2: factor2 },
            secrets: { totpSecret: secret },
            newSessionData: undefined
        }
    }

    /**
     * Authenticates the user using the saved TOTP parameters and the passed 
     * code.
     * @param _user ignored
     * @param secrets should contain `totpSecret` that was saved in the session
     *                data.
     * @param params should contain `otp`.
     */
    async authenticateUser(_user: UserInputFields | undefined,
        secrets: UserSecretsInputFields,
        params: AuthenticationParameters) : 
        Promise<void> {
        if (!secrets.totpSecret || !params.otp) {
            throw new CrossauthError(ErrorCode.InvalidToken, 
                "TOTP secret or code not given");
        }
        const code = params.otp;
        const secret = secrets.totpSecret;
        if (!gAuthenticator.check(code, secret)) {
            throw new CrossauthError(ErrorCode.InvalidToken, 
                "Invalid TOTP code");
        }
    }

    /**
     * Creates and returns a `totpSecret`
     * 
     * `allowEmptySecrets` is ignored.
     * 
     * @param username the user to create these for
     * @param _params ignored
     * @param _repeatParams  ignored
     * @returns the `totpSecret` field will be populated.
     */
    async createPersistentSecrets(username: string,
        _params: AuthenticationParameters,
        _repeatParams?: AuthenticationParameters) :
        Promise<Partial<UserSecretsInputFields>> {
        const { secret } = await this.createSecret(username);
        return { totpSecret: secret };
    }

    /**
     * Does nothing for this class
     */
    async createOneTimeSecrets(_user : User) : 
        Promise<Partial<UserSecretsInputFields>> {
        return { }
    }

    /**
     * @returns true - this class can create users
     */
    canCreateUser() : boolean {
        return true;

    }

    /**
     * @returns true - this class can update users
     */
    canUpdateUser() : boolean {
        return true;
    }

    /**
     * @returns false - users cannot update secrets
     */
    canUpdateSecrets() : boolean {
        return false;
    }

    /**
     * @returns `totpSecret`
     */
    secretNames() : string[] {
        return ["totpSecret"];
    }

    /**
     * @returns `totpSecret`
     */
    transientSecretNames() : string[] {
        return ["otp"];
    }
    
    /**
     * Does nothing for this class
     */
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    /**
     * @returns false - if email verification is enabled, it should be used 
     * for this class
     */
    skipEmailVerificationOnSignup() : boolean {
        return false;
    }
}