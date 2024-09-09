<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    import { UserState } from '@crossauth/common';
    import Totp from '$lib/components/Totp.svelte'
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    /*onMount(() => {
        if (form?.ok) {
            goto("/");
        }
    });*/
</script>
<svelte:head>
    <title>Server Login</title>
</svelte:head>
<h1>Server Login</h1>

{#if form?.factor2Required}
    <form method="POST" action="?/factor2">
        <Totp data={data} error={form?.error}/>
    </form>
{:else if form?.errorCodeName == "PasswordResetNeeded"}
{#if form?.error} 
    <p class="bg-error p-2 rounded text-slate-900">
        Please click on the link we emailed you to reset your password 
        before logging in.
    </p>
{/if}

{:else}

    <form method="POST" action="?/login">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        <input type="hidden" name="next" value={data.next ?? "/"} />
        {#if form?.error} 
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
        {/if}
        <input type="username" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" placeholder="Username" value={form?.formData?.username ?? ''}/><br>

        <input type="password" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"><br>

        <button class="btn btn-primary" type="submit">Log in</button>
        <p class="mt-3 mb-3 text-muted"><a href="/passwordreset">Forgot Password</a></p> 
    </form>
{/if}

