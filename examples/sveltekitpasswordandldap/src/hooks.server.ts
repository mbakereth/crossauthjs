// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { type Handle } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';
import { CrossauthLogger } from '@crossauth/common';
export const handle: Handle = crossauth.hooks;

CrossauthLogger.logger.level = CrossauthLogger.Debug;
