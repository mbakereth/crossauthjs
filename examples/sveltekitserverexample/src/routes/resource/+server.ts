// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { crossauth } from '$lib/server/crossauthsession';
import { json } from '@sveltejs/kit';

export const GET = async (event) => {
	return json({ok: true, user: event.locals.user?.username, timestamp: String(new Date())});
}
