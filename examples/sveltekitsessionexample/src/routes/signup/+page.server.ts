import type { PageServerLoad, Actions } from './$types';
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
	default: async ( event ) => {
        const resp = await crossauth.sessionServer?.signup(event);
        console.log(resp);
        delete resp?.exception;
        return resp;
	}
};

export const load: PageServerLoad = async ({ params }) => {
        return {
            allowedFactor2: [{name: "localpassword", friendlyName: "Local Password"}],
        };
};