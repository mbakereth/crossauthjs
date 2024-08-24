<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    import { UserState } from '@crossauth/common';
    import Totp from '$lib/components/Totp.svelte'
    import Oob from '$lib/components/Oob.svelte'
	/** @type {import('./$types').PageData} */
    export let data;
</script>
<svelte:head>
    <title>Two-Factor Authentication</title>
</svelte:head>
<h1>Login</h1>

{#if data?.factor2 == "totp"}
    <form method="POST" action={data?.action}>
        <Totp data={data} error={data?.error}/>
    </form>
{:else if data?.factor2 == "dummy" || data?.factor2 == "email"}
    <form method="POST" action={data?.action}>
        <Oob data={data} error={data?.error}/>
    </form>
{:else}
    <p class="bg-error p-2 rounded text-slate-900">Unrecognised second factor</p>
{/if}

