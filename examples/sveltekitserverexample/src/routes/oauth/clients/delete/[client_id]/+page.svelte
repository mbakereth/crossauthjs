<script>
    import { goto } from '$app/navigation';
    import DeleteClient from '$lib/components/DeleteClient.svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>

<DeleteClient data={data} form={form} back={".."} />
