import { type Handle } from '@sveltejs/kit';

export const svelteSessionHook: Handle = async function ({ event, resolve }){
	const response = await resolve(event);
    response.headers.append('set-cookie', "TESTCOOKIE=testvalue") 
    	return response;
}

export class SvelteKitSession {
    sessionHook : Handle;
    constructor() {

        this.sessionHook = async ({ event, resolve }) => {
            const response = await resolve(event);
            response.headers.append('set-cookie', "TESTCOOKIE=testvalue");
            return response;
        }
    }
}