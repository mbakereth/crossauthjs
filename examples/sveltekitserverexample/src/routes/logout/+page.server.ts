import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.logoutEndpoint.load || crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userEndpoints.logoutEndpoint.actions || crossauth.dummyActions;
