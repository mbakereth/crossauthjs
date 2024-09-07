// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import type { PageServerLoad, Actions } from './$types';
import { crossauth } from '$lib/server/crossauthsession';

export const load : PageServerLoad = crossauth.sessionServer?.userEndpoints.changePasswordEndpoint.load ?? crossauth.dummyLoad;
export const actions : Actions = crossauth.sessionServer?.userEndpoints.changePasswordEndpoint.actions ?? crossauth.dummyActions;
