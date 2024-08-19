import { crossauth } from '$lib/server/crossauthsession';
import { json } from '@sveltejs/kit';

export const GET = async (event) => {
	return json({ok: true, timestamp: new Date().toLocaleDateString()});
}
