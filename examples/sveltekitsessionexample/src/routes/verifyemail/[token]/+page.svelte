<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
</script>
<svelte:head>
    <title>Verify Email</title>
</svelte:head>
<h1>Create an Account</h1>

{#if data?.success}
    <p class="text-slate-900 bg-success p-2 rounded ">Email verification successful</p>
    <p><a href="/">Home</a></p>
{:else}
    <p class="bg-error p-2 rounded text-slate-900">Couldn't verify email: {data?.error}</p>
{/if}
