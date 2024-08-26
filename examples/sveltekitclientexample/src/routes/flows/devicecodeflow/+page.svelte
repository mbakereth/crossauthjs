<script>
    import { CrossauthLogger, OAuthBffClient } from '@crossauth/frontend';
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
	export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    console.log("devicecodeflow data", data);
    console.log("devicecodeflow form", form);

    $: completed = false;
    $: expired = false;
    $: error = "";

    onMount(() => {
        CrossauthLogger.logger.level = CrossauthLogger.Debug;
        const bffClient = new OAuthBffClient({
        enableCsrfProtection: false,
        autoRefreshUrl: "/autorefresh",
        tokensUrl: "/tokens",
        deviceCodePollUrl: "/flows/devicecodepoll",

        });
        bffClient.startDeviceCodePolling(form?.device_code, (status, pollError, location) => {
            switch (status) {
                case "complete":
                case "completeAndRedirect":
                    completed = true;
                    break;
                    case "complete":
                case "expired_token":
                    expired = true;
                    break;
                default:
                    error = pollError ?? "An unknown error occurred";
                    break;
            }
        
        });
    });

</script>
<svelte:head>
    <title>Device Code Flow</title>
</svelte:head>
<h1>Device Code Flow</h1>

{#if completed}
<p class="bg-success p-2 rounded text-slate-900">
    Device has been authorized
</p>
<p><a href="/">Home</a></p>
{:else if expired}
    <p class="bg-error p-2 rounded text-slate-900">
        Timeout waiting for authorization.  Please try again
    </p>
    <p><a href="/">Home</a></p>
{:else if error}
    <p class="bg-error p-2 rounded text-slate-900">
        {error}
    </p>
    <p><a href="/">Home</a></p>
{:else}
    {#if !form}
    <p class="bg-error p-2 rounded text-slate-900">
        This page may only be visited as a POST request
    </p>
    {:else if form.error || !form.device_code}
        <p class="bg-error p-2 rounded text-slate-900">{form?.error_description ?? form?.error ?? "An unknown error occurred"}</p>
    {:else}
        <p>
            Please visit the following URL an internet-capable device to complete authorization:
        </p>
        <pre class="mt-4">
        {form.verification_uri}
        </pre>
        <p class="-mt-2">
            and enter the following code when prompted:
        </p>
        <pre class="mt-4">
        {form.user_code}
        </pre>
        <p class="mb-6 -mt-2">Alternatively, scan the following QR code:</p>
        <p class="ml-10">
            <img src={form.verification_uri_qrdata} alt={form.verification_uri_complete} />
        </p>
    {/if}

{/if}