<script>
    import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    console.log(data)
</script>
<svelte:head>
    <title>Authorize</title>
</svelte:head>
<h1>Authorize Your Account</h1>

{#if form?.success}
    <!-- the form was successfully submitted-->
    <p class="bg-success p-2 rounded text-slate-900">
        You have authorized your access.
    </p>
    <p><a href="/">Home</a></p>
{:else}
Hi
    <!-- form not submitted or there was an error -->
    {#if data?.error}
        <!-- there was an error in the get - we cannot display the form-->
        <p class="bg-error p-2 rounded text-slate-900">
            {data?.error_description ?? "An unknown error occurred"}
        </p>
        <p><a href="/">Home</a></p>
    {:else if data?.authorizationNeeded}
        <!-- ask the user for authorization-->
        {#if form?.error}
            <!-- there was an error during form submission -->
            <p class="bg-error p-2 rounded text-slate-900">
                {form?.error_description ?? "An unknown error occurred"}
            </p>
        {/if}
        <form method="POST">
            <input type="hidden" name="csrfToken" value={data.csrfToken} />
            {#if data?.authorizationNeeded.scopes}
                <p class="bg-warning p-2 rounded text-slate-900">
                    Do you agree to authorize <b>{data?.authorizationNeeded.client_name}</b>
                    to access your account with the following scopes?
                </p>
                <ul class="ml-8 list-disc">
                    {#each data?.authorizationNeeded.scopes as scope}
                        <li>{scope}</li>
                    {/each}
                </ul>
            {:else}
                <p class="bg-warning p-2 rounded text-slate-900">
                    Do you agree to authorize <b>{data?.authorizationNeeded.client_name}</b>
                    to access your account?
                </p>
            {/if}

            <input type="hidden" name="authorized" value="true"/>
            <input type="hidden" name="response_type" value="{data?.authorizationNeeded?.response_type}"/>
            <input type="hidden" name="client_id" value="{data?.authorizationNeeded?.client_id}"/>
            <input type="hidden" name="redirect_uri" value="{data?.authorizationNeeded?.redirect_uri}"/>
            {#if data?.authorizationNeeded?.scope}
                <input type="hidden" name="scope" value="{data?.authorizationNeeded?.scope}"/>
            {/if}
            <input type="hidden" name="state" value="{data?.authorizationNeeded?.state}"/>
            {#if data?.authorizationNeeded?.code_challenge}
                <input type="hidden" name="code_challenge" value="{data?.authorizationNeeded?.code_challenge}"/>
                <input type="hidden" name="code_challenge_method" value="{data?.authorizationNeeded?.code_challenge_method}"/>
            {/if}
            <p>
                <button class="btn btn-primary" type="submit">Authorize</button>&nbsp;
                <button class="btn btn-neutral" type="button" on:click={() => goto("/")}>Cancel</button>
            
            </p>
        </form>
    {:else}
        <!-- if authorizationNeeded is not present, that means either there
             was already a redirect, meaning we didn't get here, or there
             was an error
        -->
        <p class="bg-error p-2 rounded text-slate-900">
            {data?.error_description ?? "An unknown error occurred"}
        </p>
        <p><a href="/">Home</a></p>
    {/if}
{/if}