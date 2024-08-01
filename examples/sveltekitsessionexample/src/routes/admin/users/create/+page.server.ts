import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.sessionServer?.adminEndpoints.createUserEndpoint.actions ?? crossauth.dummyActions;
export const load = crossauth.sessionServer?.adminEndpoints.createUserEndpoint.load ?? crossauth.dummyLoad;
