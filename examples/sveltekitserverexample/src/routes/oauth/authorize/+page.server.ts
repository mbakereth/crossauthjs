import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.oAuthAuthServer?.authorizeEndpoint.load  ?? crossauth.dummyLoad;
export const actions = crossauth.oAuthAuthServer?.authorizeEndpoint.actions  ?? crossauth.dummyActions;
