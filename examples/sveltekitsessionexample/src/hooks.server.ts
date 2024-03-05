import { type Handle } from '@sveltejs/kit';
import { crossauthSession } from '$lib/server//crossauthsession';
export const handle: Handle = crossauthSession.sessionHook;

