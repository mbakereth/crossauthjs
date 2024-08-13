<script>
    import { goto } from '$app/navigation';
    import EditClient from '$lib/components/EditClient.svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>

<EditClient isAdmin={false} data={data} form={form} />
