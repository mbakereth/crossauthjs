import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthAuthServer?.jwksGetEndpoint.get;