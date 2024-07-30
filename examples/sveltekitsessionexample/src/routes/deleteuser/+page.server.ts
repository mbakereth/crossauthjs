import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.deleteUserEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.deleteUserEndpoint.actions;
