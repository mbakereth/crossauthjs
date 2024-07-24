import type { PageServerLoad, Actions } from './$types';
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const load: PageServerLoad = async ( event ) => {
    return await crossauth.sessionServer?.verifyEmail(event);
};