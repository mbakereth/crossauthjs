<script>
    import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
    import { goto } from '$app/navigation';
       import { onMount } from 'svelte';
       /** @type {import('./$types').PageData} */
       export let data;
       /** @type {import('./$types').ActionData} */
       export let form;
</script>
<svelte:head>
    <title>Two Factor Authentication</title>
</svelte:head>
<h1>Two Factor Authentication</h1>

{#if form?.ok}
    {#if form?.emailVerificationRequired}
        <p class="text-slate-900 bg-info p-2 rounded ">Please check your email and
            follow the link we sent to complete registration.
        </p>
        <p><a href="/">Home</a></p>
    {:else}
        <p class="text-slate-900 bg-success p-2 rounded ">Two factor authentication configuration complete</p>
        <p><a href="/">Home</a></p>
    {/if}
{:else if form?.factor2Data?.factor2 == "totp"}
    <ConfigureTotp data={data} factor2Data={form?.factor2Data}/>
{:else}
<p class="text-slate-900 bg-error p-2 rounded ">Unknown second factor</p>
<p><a href="/">Home</a></p>
{/if}
