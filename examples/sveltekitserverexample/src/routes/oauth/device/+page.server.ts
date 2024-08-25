import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.oAuthAuthServer?.deviceEndpoint.load  ?? crossauth.dummyLoad;
export const actions = crossauth.oAuthAuthServer?.deviceEndpoint.actions  ?? crossauth.dummyActions;
