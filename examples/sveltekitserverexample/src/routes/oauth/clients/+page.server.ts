import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userClientEndpoints.searchClientsEndpoint.load;
