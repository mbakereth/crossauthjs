<script>
    import { goto } from '$app/navigation';
    import { CrossauthLogger, OAuthBffClient } from '@crossauth/frontend';
    export let data;
	import { enhance, applyAction } from '$app/forms';
    import { onMount } from 'svelte';

    let resourceResult = "Resource output will go here";
    let tokensResult = "Tokens will go here"

    onMount(() => {
        CrossauthLogger.logger.level = CrossauthLogger.Debug;
        const bffClient = new OAuthBffClient({
        enableCsrfProtection: false,
        autoRefreshUrl: "/autorefresh",
        tokensUrl: "/tokens",

        });
        bffClient.startAutoRefresh(["access"], (msg, e) => {
            if (e) console.log(e);
            alert(msg);
        });
    })

    async function clientCredentials() {
        try {
            const resp = await fetch("/flows/clientcredentials", {
                method: "POST",
                body: "{'scope': 'read write'}",
            });
            if (resp.redirected) goto(resp.url);
        } catch (e) {
            console.log(e);
        }
    }

    /** @type HTMLFormElement} */
    let deviceCodeFlowForm;

</script>

<svelte:head>
    <title>Sveltekit Example</title>
</svelte:head>
<h1>Sveltekit OAuth Client Example</h1>

<p>Logged in as {data?.user?.username ?? "nobody"}</p>
{#if data?.user}
    <p><a href="/account">Account details</a></p>
{:else}
<p><a href="/login">Login</a></p>
{/if}

<h2>OAuth Flows</h2>

<form method="POST" action="/flows/devicecodeflow" bind:this={deviceCodeFlowForm}>
    <input type="hidden" name="scope" value="read write"/>
    <input type="hidden" name="csrdfToken" value={data?.csrfToken}/>
</form>

<p><a href="flows/authzcodeflow?scope=read+write">Authorization Code Flow</a></p>
<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions a11y-missing-attribute -->
<p><a class="cursor-pointer" on:click={clientCredentials}>Client Credentials Flow</a></p>
<p><a href="flows/passwordflow">Password Flow</a></p>
<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions a11y-missing-attribute -->
<p><a class="cursor-pointer" on:click={() => {deviceCodeFlowForm.submit()}}>Device Code Flow</a></p>
<p><a href="flows/authzcodeflow?scope={data.scope}">OIDC Authorization Code Flow</a></p>
<p><a href="deletetokens">Delete my tokens</a></p>

<div class="mt-4">
    <form method="POST" action="/bff/resource" use:enhance={({ formData }) => {
        // `formElement` is this `<form>` element
        // `formData` is its `FormData` object that's about to be submitted
        // `action` is the URL to which the form is posted
        // calling `cancel()` will prevent the submission
        // `submitter` is the `HTMLElement` that caused the form to be submitted
    
        return async ({ result }) => {
            // `result` is an `ActionResult` object
            // `update` is a function which triggers the default logic that would be triggered if this callback wasn't set
            // Following is for when BFF URL returns ActionData
            /*if (result.type === 'redirect') {
                goto(result.location);
            } else if (result.status != 200) {
                resourceResult = "Error calling resource";
            } else if ("data" in result && result.data?.status != 200) {
                resourceResult = String(result.data?.error_description) ?? "Unknown error calling resource"
            } else if ("data" in result && result.data?.status == 200) {
                resourceResult = JSON.stringify(result.data.body);
            } else {
                resourceResult = "{}"
            }*/
            resourceResult = JSON.stringify(result, null, 4);
        };
    }}>
        <button type="submit" class="btn btn-neutral">Call Resource</button>
    </form>

    <pre class="mt-2 mb-2" id="result">
{resourceResult}
    </pre>
</div>

<div >
    <form method="POST" action="/tokens" use:enhance={() => {

        return async ({ result }) => {
            tokensResult = result ? JSON.stringify(result, null, 4) : "None sent";
        };
        }}>
        <button type="submit" class="btn btn-neutral">Get Tokens</button>
    </form>
    
    <pre class="mt-2 mb-2" id="result">
{tokensResult}
    </pre>
    
</div>

{#if data.user} 
    <form method="POST" action="logout">
        <button class="btn btn-primary" on:click={()=>goto("/logout")}>Logout</button>
    </form>
{/if}
