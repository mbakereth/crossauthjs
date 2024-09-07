// Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
//import { getJsonData } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import { SmsAuthenticator, type SmsAuthenticatorOptions } from './smsauth';
import twilio from 'twilio';

/**
 * This authenticator creates a one-time code and sends it in an sms using 
 * Twilio
 */
export class TwilioAuthenticator extends SmsAuthenticator {

    private accountSid : string;
    private authToken : string;

    /**
     * Constructor
     * 
     * To call this, you must have `TWILIO_ACCOUNT_SID` and
     * `TWILIO_AUTH_TOKEN` environment variables set.
     * 
     * @param options see {@link SmsAuthenticatorOptions}
     * @throws {@link @crossauth/common!CrossauthError} with
     *         {@link @crossauth/common!ErrorCode} of `Configuration`.
     */
    constructor(options : SmsAuthenticatorOptions = {}) {
        super(options);
        if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) {
            throw new CrossauthError(ErrorCode.Configuration, 
                "Must set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in environment to use Twilio")
        }
        this.accountSid = process.env.TWILIO_ACCOUNT_SID;
        this.authToken = process.env.TWILIO_AUTH_TOKEN;
    }

    /**
     * Uses Twilio to send an SMS
     * @param to number to send SMS to (starting with `+`)
     * @param body text to send
     * @returns the send message ID
     */
    protected async sendSms(to : string, body : string) : Promise<string> {
        TwilioAuthenticator.validatePhone(to);
        let sms: {
            from: string,
            to: string,
            body: string,
        } = {
            from: this.smsAuthenticatorFrom, 
            to: to,
            body: body,
        };

        const sender = twilio(this.accountSid, this.authToken);
        const message = await sender.messages.create(sms);
        return message.sid;

    }
      
}
