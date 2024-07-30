import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.sessionServer?.userEndpoints.loginEndpoint.actions;
export const load = crossauth.sessionServer?.userEndpoints.loginEndpoint.load;
