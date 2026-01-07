// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.sessionServer?.userEndpoints.signupEndpoint.actions ?? crossauth.dummyActions;
export const load = crossauth.sessionServer?.userEndpoints.signupEndpoint.load ?? crossauth.dummyLoad;
