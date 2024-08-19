import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.logoutEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.logoutEndpoint.actions;
