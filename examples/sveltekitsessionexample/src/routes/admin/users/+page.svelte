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
    <title>Users</title>
</svelte:head>
<h1>Users</h1>

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
          <th>User ID</th>
          <th>Username</th>
          <th>Email</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {#if data?.users}
            {#each data?.users as user}
                <tr>
                <th><a class="plain" href="/admin/users/edit/{user.id}">{user.id}</a></th>
                <td><a class="plain" href="/admin/users/edit/{user.id}">{user.username}</a></td>
                <td><a class="plain" href="/admin/users/edit/{user.id}">{user.email}</a></td>
                <td><a class="plain" href="/admin/users/edit/{user.id}">{user.state}</a></td>
                </tr>
            {/each}
        {/if}
      </tbody>
    </table>
  </div>
  
  <button type="button" class="btn btn-secondary" on:click={() => goto("/admin/users/create")}>New User</button>
