import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.updateUserEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.updateUserEndpoint.actions;
