// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import { redirect, json } from '@sveltejs/kit';
import { crossauth } from '$lib/server/crossauthsession';

export const GET = crossauth.oAuthClient?.bffEndpoint.get || crossauth.dummyBff;
export const POST = async (event) => await crossauth.oAuthClient?.bff(event, {method: "GET"}) ?? json({error: "server_error", error_desciption: "Method not defined"});
