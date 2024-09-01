import { redirect, json } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.bffEndpoint.get || crossauth.dummyBff;
export const POST = async (event) => await crossauth.oAuthClient?.bff(event, {method: "GET"}) ?? json({error: "server_error", error_desciption: "Method not defined"});