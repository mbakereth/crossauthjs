import { type Handle } from '@sveltejs/kit';
import { KeyStorage } from '@crossauth/backend';

export const svelteSessionHook: Handle = async function ({ event, resolve }){
	const response = await resolve(event);
    response.headers.append('set-cookie', "TESTCOOKIE=testvalue") 
    	return response;
}

export class SvelteKitSessionServerOptions {

}

export class SvelteKitSessionServer {
    sessionHook : Handle;
    keyStorage : KeyStorage;

    constructor(keyStorage : KeyStorage, _options : SvelteKitSessionServerOptions = {}) {

        this.keyStorage = keyStorage;
        
        this.sessionHook = async ({ event, resolve }) => {
            const response = await resolve(event);
            response.headers.append('set-cookie', "TESTCOOKIE=testvalue");
            return response;
        }
    }
}