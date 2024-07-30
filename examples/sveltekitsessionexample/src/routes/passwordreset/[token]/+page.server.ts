import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.passwordResetTokenEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.passwordResetTokenEndpoint.actions;
