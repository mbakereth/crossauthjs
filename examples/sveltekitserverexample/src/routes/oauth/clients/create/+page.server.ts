import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userClientEndpoints.createClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userClientEndpoints.createClientEndpoint.actions ?? crossauth.dummyActions;
