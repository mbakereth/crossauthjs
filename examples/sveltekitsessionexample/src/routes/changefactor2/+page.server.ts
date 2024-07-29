import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
    default: async ( event ) => {
        const resp = await crossauth.sessionServer?.changeFactor2(event);
        delete resp?.exception;
        return resp;
    }
};

export const load: PageServerLoad = async ( event ) => {
    let allowedFactor2 = crossauth.sessionServer?.allowedFactor2 ??
        [{name: "none", friendlyName: "None"}];
    let required = event.url.searchParams.get("required") == "true";
    return {
        allowedFactor2,
        required,
    };
};