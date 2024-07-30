import type { PageServerLoad } from './$types';
import { crossauth } from '$lib/server/crossauthsession';
import { CrossauthLogger, j} from '@crossauth/common';

export const load: PageServerLoad = async ( event ) => {
    const resp = await crossauth.sessionServer?.searchUsers(event);
    delete resp?.exception;
    return resp;
};
