// Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.adminEndpoints.deleteUserEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.adminEndpoints.deleteUserEndpoint.actions ?? crossauth.dummyActions;
