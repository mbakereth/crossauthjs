<script>
    import { goto } from '$app/navigation';

    export let data;
</script>
<svelte:head>
    <title>Site Admin</title>
</svelte:head>
<h1>Site Admin</h1>

<h4>Logged in as {data.user?.username}</h4>

<p><a href="/admin/users">Users</a></p>
<p><a href="/admin/oauth/clients">OAuth Clients</a></p>
<p><a href="/">Home</a></p>

<form method="POST" action="logout">
    <button class="btn btn-primary" on:click={()=>goto("/logout")}>Logout</button>
</form>
