<script>
    import { goto } from '$app/navigation';
    export let data;
    export let factor2Data;
</script>
<h2>Configure Two-Factor Authentication</h2>

<ol class="list-decimal ml-4">
    <li class="mb-2">Install Google Authenticator on your phone from the App Store or Play Store</li>
    <li class="mb-2">Scan the QR Code in the Authenticator app, or enter the following code manually:
        <pre>{factor2Data.userData.totpsecret }</pre>
    </li>
    <li class="mb-2">Enter the code that you see in the app in the text field below and click Submit.</li>
</ol>

<p><img src="{ factor2Data.userData.qr }" class="ml-4 mt-4" alt="factor2Data.userData.totpsecret"/></p>

<form method="POST" action="/configurefactor2">

    <input type="hidden" name="next" value="{ data.next }"/>
    <input type="hidden" name="csrfToken" value="{ factor2Data.csrfToken }"/>
    <div class="form-control mt-2 ml-3">
        <label class="label" for="otp">
        <span class="label-text">Code</span>
        </label>
        <label class="input-group">
            <input type="password" id="otp" name="otp" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
        </label>
    </div>

    <button class="btn btn-primary ml-4" type="submit">Submit</button>
</form>
