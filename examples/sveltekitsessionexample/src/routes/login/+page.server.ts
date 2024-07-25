import type { PageServerLoad, Actions } from './$types';
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
	login: async ( event ) => {
                const resp = await crossauth.sessionServer?.login(event);
                if (resp?.success == true && !resp?.factor2Required) throw redirect(302, '/');
                delete resp?.exception;
                return resp;
	},
        factor2: async ( event ) => {
                const resp = await crossauth.sessionServer?.loginFactor2(event);
                if (resp?.success == true && !resp?.factor2Required) throw redirect(302, '/');
                delete resp?.exception;
                return resp;

        },
};

export const load: PageServerLoad = async ({ params }) => {
        return {
            next: "/test",
        };
};