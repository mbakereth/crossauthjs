// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.authorizationCodeFlowEndpoint.get || crossauth.dummyLoad;
