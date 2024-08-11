import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

export const load : PageServerLoad = crossauth.sessionServer?.adminEndpoints.changePasswordEndpoint.load ?? crossauth.dummyLoad;
export const actions : Actions = crossauth.sessionServer?.adminEndpoints.changePasswordEndpoint.actions ?? crossauth.dummyActions;
