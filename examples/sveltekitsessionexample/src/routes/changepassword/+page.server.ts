import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.changePasswordEndpoint.load;
export const actions = crossauth.sessionServer?.userEndpoints.changePasswordEndpoint.actions;
