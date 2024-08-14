<script>
    import { goto } from '$app/navigation';
    import CreateClient from '$lib/components/CreateClient.svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>

<svelte:head>
    <title>Create Client</title>
</svelte:head>
<h1>Create OAuth Client</h1>

<CreateClient isAdmin={true} data={data} form={form} back={"."}/>

