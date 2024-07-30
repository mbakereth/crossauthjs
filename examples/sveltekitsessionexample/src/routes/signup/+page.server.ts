import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.sessionServer?.userEndpoints.signupEndpoint.actions;
export const load = crossauth.sessionServer?.userEndpoints.signupEndpoint.load;
