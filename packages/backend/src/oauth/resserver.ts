import jwt from 'jsonwebtoken';
import { CrossauthLogger, j } from '@crossauth/common';

export class OAuthResourceServer {
    
    static async authorized(accessToken : string, secretOrPublicKey : string, clockTolerance : number = 10) : Promise<{[key:string]: any}|undefined>{
        return  new Promise((resolve, reject) => {
            jwt.verify(accessToken, secretOrPublicKey, {clockTolerance: clockTolerance, complete: true}, 
                (error: Error | null,
                decoded: {[key:string]:any} | undefined) => {
                    if (decoded) {
                        resolve(decoded);
                    } else if (error) { 
                        CrossauthLogger.logger.error(j({err: error}));
                        resolve(undefined);
                    } else {
                        CrossauthLogger.logger.error(j({err: error}));
                        reject(undefined);
                    }
                });
        });
    }
};
