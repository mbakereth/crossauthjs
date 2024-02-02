import QRCode from 'qrcode';
import { authenticator as gAuthenticator } from 'otplib';
import type { User, Key, UserSecretsInputFields } from '../interfaces.ts';
import { getJsonData } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { CrossauthLogger, j } from '../logger.ts';
import { Authenticator, type AuthenticationParameters, AuthenticationOptions } from './auth';

export class TotpAuthenticator extends Authenticator {

    private appName : string;

    constructor(appName : string, options? : AuthenticationOptions) {
        super({friendlyName : "Google Authenticator", ...options});
        this.appName = appName;
    }

    private async createSecret(username : string, secret? : string) : Promise<{qrUrl : string, secret: string}> {
        if (!secret) secret = gAuthenticator.generateSecret();
        let qrUrl = "";
        await QRCode.toDataURL(gAuthenticator.keyuri(username, this.appName, secret))
            .then((url) => {
                    qrUrl = url;
            })
            .catch((err) => {
                CrossauthLogger.logger.debug(j({err: err}));
                throw new CrossauthError(ErrorCode.UnknownError, "Couldn't generate 2FA URL");
            });

        return { qrUrl, secret };   
    }

    private async getSecretFromSession(
        username : string, 
        sessionKey : Key) : Promise<{qrUrl: string, secret: string, factor2: string}> {
        const data = getJsonData(sessionKey);
        if (!("totpSecret" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "TOTP data not in session");
        if (!("factor2" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "TOTP factor name not in session");
        const savedSecret = data.totpSecret;
        const { qrUrl, secret } = await this.createSecret(username, savedSecret);

        return {qrUrl, secret, factor2: data.factor2}
        
    }

    async prepareAuthentication(username : string) : Promise<{userData: {[key:string]: any}, sessionData: {[key:string]: any}}|undefined> {
        const { qrUrl, secret } = await this.createSecret(username);

        const userData = {username: username, qr: qrUrl, totpSecret: secret, factor2: this.factorName};
        const sessionData = {username: username, totpSecret: secret, factor2: this.factorName}
        return { userData, sessionData};
    }

    async reprepareAuthentication(username : string, sessionKey : Key) : Promise<{userData: {[key:string]: any}, secrets: Partial<UserSecretsInputFields>}|undefined> {
        const { qrUrl, secret, factor2 } = await this.getSecretFromSession(username, sessionKey);
        return { userData: {qr: qrUrl, totpSecret: secret, factor2: factor2}, secrets: {totpSecret: secret}}
    }

    async authenticateUser(_user : User|undefined, secrets : UserSecretsInputFields, params: AuthenticationParameters) : Promise<void> {
        if (!secrets.totpSecret || !params.totpCode) {
            throw new CrossauthError(ErrorCode.Unauthorized, "TOTP secret or code not given");
        }
        const code = params.totpCode;
        const secret = secrets.totpSecret;
        if (!gAuthenticator.check(code, secret)) {
            throw new CrossauthError(ErrorCode.Unauthorized, "Invalid TOTP code");
        }
    }

    async createSecrets(username : string, _params: AuthenticationParameters, _repeatParams?: AuthenticationParameters) : Promise<Partial<UserSecretsInputFields>> {
        const { secret } = await this.createSecret(username);
        return { totpSecret: secret };
    }

    canCreateUser() : boolean {
        return true;

    }
    canUpdateUser() : boolean {
        return true;
    }
    secretNames() : string[] {
        return ["totpSecret"];
    }
    validateSecrets(_params : AuthenticationParameters) : string[] {
        return [];
    }

    skipEmailVerificationOnSignup() : boolean {
        return false;
    }
}