import { crossauth } from '$lib/server/crossauthsession';

export const POST = crossauth.oAuthAuthServer?.deviceAuthorizationEndpoint.post;
