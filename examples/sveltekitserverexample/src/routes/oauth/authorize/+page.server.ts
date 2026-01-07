// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.oAuthAuthServer?.authorizeEndpoint.load  ?? crossauth.dummyLoad;
export const actions = crossauth.oAuthAuthServer?.authorizeEndpoint.actions  ?? crossauth.dummyActions;
