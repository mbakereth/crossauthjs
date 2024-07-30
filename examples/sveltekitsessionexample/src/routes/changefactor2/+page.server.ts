import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.changeFactor2Endpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.changeFactor2Endpoint.actions;
