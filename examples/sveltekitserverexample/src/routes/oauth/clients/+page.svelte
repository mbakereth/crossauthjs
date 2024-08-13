<script>
    import SearchClients from '$lib/components/SearchClients.svelte';
    import { goto } from '$app/navigation';
    /** @type {import('./$types').PageData} */
    export let data;
    let skip = data?.skip ?? 0;
    let take = data?.take ?? 10;
    let searchTerm = data?.search ?? "";
    $: searchParam = data?.search ? "&search=" + encodeURIComponent(data?.search) : "";

    function next() {
        if (data?.hasNext) goto("/admin/users?skip="+(skip+take)+"&take="+take+searchParam);
    }

    function previous() {
        if (data?.hasPrevious) goto("/admin/users?skip="+(skip-take)+"&take="+take+searchParam);
    }

    // @ts-ignore
    function search(e) {
        if (e.keyCode == 13) {
            if (searchTerm) goto("/admin/users?search=" + searchTerm);
            else goto("/admin/users");
        }
    }
</script>

<svelte:head>
    <title>Clients</title>
</svelte:head>

<SearchClients data={data} isAdmin={false} />
<p><a href="/account">My Account</a></p>