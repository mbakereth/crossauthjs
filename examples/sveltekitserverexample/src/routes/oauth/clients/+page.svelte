<script>
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
<h1>Clients</h1>

{#if data?.error} 
<p class="bg-error p-2 rounded text-slate-900">{data?.error}</p>
{/if}

<form method="POST" action="?/login">
    <input type="text" 
        id="search" 
        name="search" 
        class="input input-bordered w-full max-w-xs mb-4" 
        placeholder="Search" 
        bind:value={searchTerm}
        on:keypress|preventDefault={search}/>
</form>

<div class="overflow-x-auto">
    <table class="table">
      <!-- head -->
      <thead>
        <tr>
          <th>Name</th>
          <th>Client ID</th>
        </tr>
      </thead>
      <tbody>
        {#if data?.clients}
            {#each data?.clients as client}
                <tr>
                <th><a class="plain" href="/oauth/clients/edit/{client.clientId}">{client.clientName}</a></th>
                <td><a class="plain" href="/oauth/clients/edit/{client.clientId}">{client.clientId}</a></td>
                </tr>
            {/each}
        {/if}
      </tbody>
    </table>
</div>
  
<button type="button" class="btn btn-secondary" on:click={() => goto("/oauth/clients/create")}>New Client</button>

<p><a href="/admin">Admin Home</a></p>