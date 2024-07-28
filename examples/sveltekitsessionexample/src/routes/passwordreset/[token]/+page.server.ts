import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';
import { JsonOrFormData } from '@crossauth/sveltekit';
import { CrossauthError, ErrorCode, j, CrossauthLogger } from '@crossauth/common';
import { request } from 'http';

/** @type {import('./$types').Actions} */
export const actions : Actions = {
	default: async ( event ) => {

        CrossauthLogger.logger.debug(j({msg:"Action " + event.request.method}))
        // we already visited this URL and used it to initiate 2FA
        // - execute as normal to perform password reset
        const resp = await crossauth.sessionServer?.resetPassword(event);
        delete resp?.exception;
        return resp;    
    }
};

export const load: PageServerLoad = async (event) => {
    try {
        CrossauthLogger.logger.debug(j({msg:"PageServerLoad " + event.request.method}));
        const resp = await crossauth.sessionServer?.validatePasswordResetToken(event);
        if (!resp?.user) throw new CrossauthError(ErrorCode.InvalidToken, "The password reset token is invalid");
        if (!event.locals.sessionId) 
            await crossauth.sessionServer?.createAnonymousSession(event, {user: {username: resp.user.username}});
        return {
            tokenValidated: resp?.success ?? false,
            error: resp?.error,
        };    
    } catch (e) {
        const ce = CrossauthError.asCrossauthError(e);
        CrossauthLogger.logger.debug(j({err: ce}));
        CrossauthLogger.logger.error(j({cerr: ce}));
        return {
            tokenValidated: false,
            error: ce.message,
        };    
    }
};