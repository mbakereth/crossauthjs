<script>
    import { goto } from '$app/navigation';
    export let data;
    export let isAdmin;
    let skip = data?.skip ?? 0;
    let take = data?.take ?? 10;
    let searchTerm = data?.search ?? "";
    $: searchParam = data?.search ? "&search=" + encodeURIComponent(data?.search) : "";

    // @ts-ignore
    function search(e) {
        if (e.keyCode == 13) {
            if (searchTerm) goto("/admin/users?search=" + searchTerm);
            else goto("/admin/users");
        }
    }
</script>

{#if data?.error} 
<p class="bg-error p-2 rounded text-slate-900">{data?.error}</p>
{/if}

<form method="GET" >
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
            {#if isAdmin}
                <th>User</th>
            {/if}
          <th>Client ID</th>
        </tr>
      </thead>
      <tbody>
        {#if data?.clients}
            {#each data?.clients as client}
                <tr>
                <th><a class="plain" href="clients/edit/{client.clientId}">{client.clientName}</a></th>
                {#if isAdmin}
                    <th><a class="plain" href="clients/edit/{client.clientId}">{client.user?.username}</a></th>
                {/if}
                <td><a class="plain" href="clients/edit/{client.clientId}">{client.clientId}</a></td>
                </tr>
            {/each}
        {/if}
      </tbody>
    </table>
</div>
  
<button type="button" class="btn btn-neutral mt-4" disabled={!data?.hasPrevious} on:click={() => goto("clients?skip="+(skip+take)+"&take="+take+searchParam)}>Prev</button>&nbsp;
<button type="button" class="btn btn-secondary mt-4" disabled={!data?.hasNext} on:click={() => goto("clients?skip="+(skip-take)+"&take="+take+searchParam)}>Next</button>&nbsp;
<button type="button" class="btn btn-secondary mt-4" on:click={() => goto("clients/create"+(data?.clientUserId ? "?userid="+data?.clientUserId : ""))}>New Client</button>
