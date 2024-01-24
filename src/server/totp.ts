import QRCode from 'qrcode';
import { authenticator as gAuthenticator } from 'otplib';
import type { User, Key } from '../interfaces.ts';
import { getJsonData } from '../interfaces.ts';
import { ErrorCode, CrossauthError } from '../error.ts';
import { SessionCookie } from './cookieauth.ts';
import { KeyStorage } from './storage.ts';
import { CrossauthLogger, j } from '../logger.ts';

export class Totp {

    private appName : string;
    private keyStorage : KeyStorage;

    constructor(appName : string, keyStorage : KeyStorage ) {
        this.appName = appName;
        this.keyStorage = keyStorage;
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
                throw new CrossauthError(ErrorCode.UnknownError, "Couldn't generate TOTP URL");
            });

        return { qrUrl, secret };   
    }

    async createAndStoreSecret(
        username : string, 
        sessionId : string) : Promise<{qrUrl: string, secret: string}> {
        const { qrUrl, secret } = await this.createSecret(username);

        await this.keyStorage.updateKey({
            value: SessionCookie.hashSessionKey(sessionId),
            data: JSON.stringify({username: username, secret: secret}),
        });

        return { qrUrl, secret}
    }

    async getSecretFromSession(
        username : string, 
        sessionId : string) : Promise<{qrUrl: string, secret: string}> {
        const sessionKey = await this.keyStorage.getKey(SessionCookie.hashSessionKey(sessionId));
        const data = getJsonData(sessionKey);
        if (!("secret" in data)) throw new CrossauthError(ErrorCode.Unauthorized, "TOTP data not in session");
        const savedSecret = data.secret;
        const { qrUrl, secret } = await this.createSecret(username, savedSecret);

        return {qrUrl, secret}
        
    }

    async validateCodeFromKey(code : string, sessionKey : Key) : Promise<{username : string, secret : string}> {

        let {username, secret} = getJsonData(sessionKey);
        if (!username || !secret) throw new CrossauthError(ErrorCode.Unauthorized, "TOTP has not been requested for this session");

        if (!gAuthenticator.check(code, secret)) {
            throw new CrossauthError(ErrorCode.Unauthorized, "Invalid code");
        }
        return { username, secret };
    }

    async validateCodeFromUser(code : string, user : User) : Promise<{username : string, secret : string}> {

        if (!("totpSecret" in user) || user.totpSecret == "") throw new CrossauthError(ErrorCode.Unauthorized, "TOTP has not been activated for this user");

        if (!gAuthenticator.check(code, user.totpSecret)) {
            throw new CrossauthError(ErrorCode.Unauthorized, "Invalid code");
        }

        return { username: user.username, secret: user.totpSecret };
    }
}