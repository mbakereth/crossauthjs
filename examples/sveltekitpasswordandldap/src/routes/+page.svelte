<script>
    import { goto } from "$app/navigation";
    export let data;
</script>

<svelte:head>
    <title>Sveltekit Password & LDAP Example</title>
</svelte:head>
<h1>Sveltekit Password & LDAP Example</h1>

<p>Logged in as {data?.user?.username ?? "nobody"}</p>

{#if data.user} 
    <form method="POST" action="logout">
        <button class="btn btn-primary" on:click={()=>goto("/logout")}>Logout</button>
    </form>
{/if}
