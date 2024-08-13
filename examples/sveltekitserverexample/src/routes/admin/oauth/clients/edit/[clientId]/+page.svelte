<script>
    import { goto } from '$app/navigation';
    import EditClient from '$lib/components/EditClient.svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>

<svelte:head>
    <title>Update Client</title>
</svelte:head>
<h1>Update OAuth Client</h1>

<EditClient isAdmin={true} data={data} form={form} back={".."}/>

