import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.updateUserEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userEndpoints.updateUserEndpoint.actions ?? crossauth.dummyActions;
