import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
    change: async ( event ) => {
        const resp = await crossauth.sessionServer?.changeFactor2(event);
        delete resp?.exception;
        return resp;
    },
    reconfigure: async ( event ) => {
        const resp = await crossauth.sessionServer?.reconfigureFactor2(event);
        delete resp?.exception;
        return resp;
    },
};

export const load: PageServerLoad = async ( event ) => {
    let allowedFactor2 = crossauth.sessionServer?.allowedFactor2 ??
        [{name: "none", friendlyName: "None", configurable: false}];
    console.log(allowedFactor2)
    let required = event.url.searchParams.get("required") == "true";
    return {
        allowedFactor2,
        required,
    };
};