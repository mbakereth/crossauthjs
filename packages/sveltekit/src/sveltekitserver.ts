import { SvelteKitSessionServer, type SvelteKitSessionServerOptions } from './sveltekitsession';
import { UserStorage, KeyStorage, Authenticator } from '@crossauth/backend';

export interface SvelteKitServerOptions {

}

export class SvelteKitServer {
    userStorage : UserStorage;
    sessionServer? : SvelteKitSessionServer;
    constructor(userStorage: UserStorage, {
        session
    } : {
        session? : {
            keyStorage: KeyStorage, 
            authenticators: {[key:string]: Authenticator}, 
            options?: SvelteKitSessionServerOptions,
}
    }, options : SvelteKitServerOptions = {}) {

        this.userStorage = userStorage;
        if (session) {
            this.sessionServer = new SvelteKitSessionServer(session.keyStorage, {...session.options, ...options});
        }
    }
}
