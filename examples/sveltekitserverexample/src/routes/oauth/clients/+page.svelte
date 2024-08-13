<script>
    import SearchClients from '$lib/components/SearchClients.svelte';
    import { goto } from '$app/navigation';
    /** @type {import('./$types').PageData} */
    export let data;
</script>

<svelte:head>
    <title>Clients</title>
</svelte:head>

<SearchClients data={data} isAdmin={false} />
<p><a href="/account">My Account</a></p>