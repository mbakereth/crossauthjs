import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminClientEndpoints.updateClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.adminClientEndpoints.updateClientEndpoint.actions ?? crossauth.dummyActions;
