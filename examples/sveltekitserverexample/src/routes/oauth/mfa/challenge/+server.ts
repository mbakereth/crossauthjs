import { crossauth } from '$lib/server/crossauthsession';

export const POST = crossauth.oAuthAuthServer?.mfaChallengeEndpoint.post;
