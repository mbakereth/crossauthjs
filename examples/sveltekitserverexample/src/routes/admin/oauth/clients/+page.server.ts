import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminClientEndpoints.searchClientsEndpoint.load;
