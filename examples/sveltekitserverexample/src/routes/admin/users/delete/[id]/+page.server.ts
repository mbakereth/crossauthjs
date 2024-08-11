import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminEndpoints.deleteUserEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.adminEndpoints.deleteUserEndpoint.actions ?? crossauth.dummyActions;
