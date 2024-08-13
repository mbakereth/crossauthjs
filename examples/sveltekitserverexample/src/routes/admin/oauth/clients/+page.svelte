<script>
    import SearchClients from '$lib/components/SearchClients.svelte';
    import { goto } from '$app/navigation';
    /** @type {import('./$types').PageData} */
    export let data;
</script>

<svelte:head>
    <title>Clients</title>
</svelte:head>

<h1>Clients</h1>

<SearchClients data={data} isAdmin={false} />
<p><a href="..">Admin Page</a></p>