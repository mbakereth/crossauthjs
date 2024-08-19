import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.redirectUriEndpoint.get;
