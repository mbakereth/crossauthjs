<script>
    import { goto, invalidate, invalidateAll } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    //export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    onMount(() => {
        if (form?.ok) {
            invalidateAll();
        }
    });
    
</script>
<svelte:head>
    <title>Logout</title>
</svelte:head>
<h1>Logout</h1>

{#if form?.error} 
    <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
{:else}
<p class="bg-success p-2 rounded text-slate-900">You have been logged out</p>
{/if}

<p><a href="/login">Login</a></p>
