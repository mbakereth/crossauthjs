import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userClientEndpoints.updateClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userClientEndpoints.updateClientEndpoint.actions ?? crossauth.dummyActions;
