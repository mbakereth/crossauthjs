import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminEndpoints.updateUserEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.adminEndpoints.updateUserEndpoint.actions ?? crossauth.dummyActions;
