//import { getJsonData } from '../../interfaces.ts';
import { ErrorCode, CrossauthError } from '@crossauth/common';
import nunjucks from "nunjucks";
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
     * @param options see {@link TwilioAuthenticatorOptions}
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

    protected async sendToken(to : string, otp : string) : Promise<string> {
        TwilioAuthenticator.validatePhone(to);
        let data = {otp: otp};
        let sms: {
            from: string,
            to: string,
            body: string,
        } = {
            from: this.smsAuthenticatorFrom, 
            to: to,
            body: nunjucks.render(this.smsAuthenticatorBody, data)
        };

        const sender = twilio(this.accountSid, this.authToken);
        const message = await sender.messages.create(sms);
        return message.sid;

    }
      
}
