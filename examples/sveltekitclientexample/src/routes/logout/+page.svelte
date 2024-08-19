<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    //export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    /*onMount(() => {
        if (form?.success) {
            goto("/");
        }
    });*/
</script>
<svelte:head>
    <title>Logout</title>
</svelte:head>
<h1>Login</h1>

{#if form?.error} 
    <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
{:else}
<p class="bg-success p-2 rounded text-slate-900">You have been logged out</p>
{/if}

<p><a href="/">Home</a></p>
