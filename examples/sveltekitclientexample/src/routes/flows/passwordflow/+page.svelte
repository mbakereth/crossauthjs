<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    import { UserState } from '@crossauth/common';
    import MfaOtp from '$lib/components/MfaOtp.svelte'
    import MfaOob from '$lib/components/MfaOob.svelte'
	/** @type {import('./$types').PageData} */
	export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>
<svelte:head>
    <title>Password Flow Login</title>
</svelte:head>
<h1>Password Flow Login</h1>

{#if form?.challenge_type == "otp"}
    <form method="POST" action="?/passwordOtp">
        <MfaOtp data={data} form={form} error={form?.error}/>
    </form>
{:else if form?.challenge_type == "oob"}
    <form method="POST" action="?/passwordOob">
        <MfaOob data={data} form={form} error={form?.error}/>
    </form>
{:else}
    <form method="POST" action="?/password">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        {#if form?.error} 
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error_description ?? form?.error}</p>
        {/if}
        <input type="hidden" id="scope" name="scope" value="read write"/><br>
        <input type="username" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" placeholder="Username" value={form?.formData?.username ?? ''}/><br>

        <input type="password" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"><br>

        <button class="btn btn-primary" type="submit">Log in</button>
    </form>
{/if}

