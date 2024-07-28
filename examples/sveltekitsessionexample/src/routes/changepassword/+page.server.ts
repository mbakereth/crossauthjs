import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
	default: async ( event ) => {
        const resp = await crossauth.sessionServer?.changePassword(event);
        delete resp?.exception;
        return resp;
	}
};

export const load: PageServerLoad = async ({ params }) => {
        return {
        };
};