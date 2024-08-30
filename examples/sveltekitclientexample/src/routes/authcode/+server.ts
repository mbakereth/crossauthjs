import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.redirect_uriEndpoint.get;
