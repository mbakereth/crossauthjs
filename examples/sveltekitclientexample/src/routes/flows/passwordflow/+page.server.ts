// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { redirect } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const actions = crossauth.oAuthClient?.passwordFlowEndpoint.actions ??crossauth.dummyActions;
