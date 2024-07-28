import type { PageServerLoad, Actions } from './$types';
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const load: PageServerLoad = async (event) => {
    console.log("Requesting factor2")
    const resp = await crossauth.sessionServer?.requestFactor2(event);
    if (resp && !resp.error && event.url.searchParams.get("error"))
        resp.error = event.url.searchParams.get("error") ?? undefined;
    return resp;
};