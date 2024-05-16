import { CrossauthError, ErrorCode, OAuthTokenConsumerBase } from "@crossauth/common";

export class OAuthTokenConsumer extends OAuthTokenConsumerBase {
   
    /**
     * SHA256 and Base64-url-encodes the given test
     * @param plaintext the text to encode
     * @returns the SHA256 hash, Base64-url-encode
     */
    async hash(plaintext :string) : Promise<string> {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const hash = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hash)); 
        return btoa(hashArray.reduce((acc, current) => acc + String.fromCharCode(current), ""))
            .replace(/\//g, "_")
            .replace(/\+/g, "-")
            .replace(/=+$/, "");
    }
    
}