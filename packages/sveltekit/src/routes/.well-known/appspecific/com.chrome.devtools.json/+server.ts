import { fileURLToPath } from 'url';
import path from 'path';
import { json, type RequestEvent } from '@sveltejs/kit';
import { error } from '@sveltejs/kit';
import { dev } from '$app/environment';

export const GET = async (event : RequestEvent) => {
    if (dev) {
        //const __filename = fileURLToPath(import.meta.url);
        //let dir = path.dirname(__filename);
        const dir = process.cwd();
        return json({
            "workspace": {
                "root": dir,
                "uuid": "3975c6da-e6fe-4029-a1de-4df86199a2d6"
            }
        })
    } else {
        throw error(401, 'Only available in dev mode');

    }
}
