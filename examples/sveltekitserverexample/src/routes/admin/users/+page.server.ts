import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminEndpoints.searchUsersEndpoint.load ?? crossauth.dummyLoad;
