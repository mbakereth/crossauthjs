<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    function cancel() {
        goto("/account");
    }
</script>
<svelte:head>
    <title>Delete Your Account</title>
</svelte:head>
<h1>Delete Your Account</h1>

{#if form?.success}
    <p class="bg-success p-2 rounded text-slate-900">Your account has been deleted</p>
    <p><a href="/">Home</a></p>
{:else}
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {/if}
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        <p class="bg-success p-2 rounded text-slate-900">Are you sure you want to delete your account?</p>

        <button class="btn btn-primary" type="submit">Yes</button>
        &nbsp;
        <button type="button" class="btn btn-secondary" on:click={cancel}>No</button>
    </form>
{/if}