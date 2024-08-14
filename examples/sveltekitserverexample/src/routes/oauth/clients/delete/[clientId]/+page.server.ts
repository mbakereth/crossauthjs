import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userClientEndpoints.deleteClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userClientEndpoints.deleteClientEndpoint.actions ?? crossauth.dummyActions;
