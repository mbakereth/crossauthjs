import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminClientEndpoints.createClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.adminClientEndpoints.createClientEndpoint.actions ?? crossauth.dummyActions;
