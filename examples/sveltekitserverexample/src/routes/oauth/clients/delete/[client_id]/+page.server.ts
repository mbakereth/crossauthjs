// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { crossauth } from '$lib/server/crossauthsession';

export const load = crossauth.sessionServer?.userClientEndpoints.deleteClientEndpoint.load ?? crossauth.dummyLoad;
export const actions = crossauth.sessionServer?.userClientEndpoints.deleteClientEndpoint.actions ?? crossauth.dummyActions;
