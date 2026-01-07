// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userEndpoints.configureFactor2Endpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userEndpoints.configureFactor2Endpoint.actions ?? crossauth.dummyActions;
