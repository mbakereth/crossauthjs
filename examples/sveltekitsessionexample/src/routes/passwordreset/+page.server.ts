import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.passwordResetEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.passwordResetEndpoint.actions;
