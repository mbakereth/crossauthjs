import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
	default: async ( event ) => {
        const resp = await crossauth.sessionServer?.signup(event);
        delete resp?.exception;
        return resp;
	}
};

export const load: PageServerLoad = async ({ params }) => {
    let allowedFactor2 = crossauth.sessionServer?.allowedFactor2 ??
        [{name: "none", friendlyName: "None"}];
    return {
        allowedFactor2
    };
};