import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.oAuthClient?.startDeviceCodeFlowEndpoint.actions ??crossauth.dummyActions;
