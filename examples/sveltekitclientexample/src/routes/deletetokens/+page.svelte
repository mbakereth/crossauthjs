<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    import { UserState } from '@crossauth/common';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>
<svelte:head>
    <title>Delete Tokens</title>
</svelte:head>
<h1>Delete Tokens</h1>

{#if form?.ok == true}
    <p class="bg-success p-2 rounded text-slate-900">Your tokens have been deleted.</p>
    <p><a href="/">Home</a></p>
{:else}
    {#if form?.ok == false}
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error ??"An unknown error occurred"}</p>
    {/if}
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        {#if form?.error} 
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
        {/if}
        <p class="bg-info p-2 rounded text-slate-900 mb-4">Really delete your tokens?</p>
        <p>
            <button class="btn btn-primary" type="submit">Delete</button>&nbsp;
            <button class="btn btn-neutral" type="button" on:click={ () => goto("/")}>Cancel</button>
        </p>
    </form>
{/if}

