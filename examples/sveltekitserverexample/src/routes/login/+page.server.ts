import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.sessionServer?.userEndpoints.loginEndpoint.actions ??crossauth.dummyActions;
export const load = crossauth.sessionServer?.userEndpoints.loginEndpoint.load ?? crossauth.dummyLoad;
