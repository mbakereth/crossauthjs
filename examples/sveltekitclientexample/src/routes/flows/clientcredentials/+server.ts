import { crossauth } from '$lib/server/crossauthsession';

export const POST = crossauth.oAuthClient?.clientCredentialsFlowEndpoint.post;