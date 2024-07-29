import type { PageServerLoad, Actions } from './$types';
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const load: PageServerLoad = async ( event ) => {
    const resp = await crossauth.sessionServer?.verifyEmail(event);
    delete resp?.exception;
    return resp;
};