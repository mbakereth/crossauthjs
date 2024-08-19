<script>
    import { goto } from '$app/navigation';
    export let data;
	import { enhance, applyAction } from '$app/forms';

    let resourceResult = "Resource output will go here"
</script>

<svelte:head>
    <title>Sveltekit Example</title>
</svelte:head>
<h1>Sveltekit OAuth Client Example</h1>

<p>Logged in as {data?.user?.username ?? "nobody"}</p>
<p><a href="/account">Account details</a></p>

<h2>OAuth Flows</h2>

<p><a href="flows/authzcodeflow?scope=read+write">Authorization Code Flow</a></p>
<p><a href="flows/clientcredentialsflow">Client Credentials Flow</a></p>
<p><a href="flows/passwordflow">Password Flow</a></p>
<p><a href="flows/oidcauthzcodeflow">OIDC Authorization Code Flow</a></p>

<form method="POST" action="/bff/resource?/get" use:enhance={({ formData }) => {
    // `formElement` is this `<form>` element
    // `formData` is its `FormData` object that's about to be submitted
    // `action` is the URL to which the form is posted
    // calling `cancel()` will prevent the submission
    // `submitter` is the `HTMLElement` that caused the form to be submitted

    return async ({ result }) => {
        // `result` is an `ActionResult` object
        // `update` is a function which triggers the default logic that would be triggered if this callback wasn't set
        if (result.type === 'redirect') {
            goto(result.location);
        } else if (result.status != 200) {
            resourceResult = "Error calling resource";
        } else if ("data" in result && result.data?.status != 200) {
            resourceResult = String(result.data?.error_description) ?? "Unknown error calling resource"
        } else if ("data" in result && result.data?.status == 200) {
            resourceResult = JSON.stringify(result.data.body);
        } else {
            resourceResult = "{}"
        }
    };
}}>
    <button type="submit" class="btn btn-neutral">Call Resource</button>
</form>
<pre id="result">
    {resourceResult}
</pre>

{#if data.user} 
    <form method="POST" action="logout">
        <button class="btn btn-primary" on:click={()=>goto("/logout")}>Logout</button>
    </form>
{/if}
