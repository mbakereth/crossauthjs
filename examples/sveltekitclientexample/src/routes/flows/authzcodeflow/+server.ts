import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.authorizationCodeFlowEndpoint.get || crossauth.dummyLoad;
