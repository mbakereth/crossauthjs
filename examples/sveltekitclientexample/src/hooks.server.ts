import { type Handle } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';
import { CrossauthLogger } from '@crossauth/common';
export const handle: Handle = crossauth.hooks;

CrossauthLogger.logger.level = CrossauthLogger.Debug;
