<script>
    import { goto } from '$app/navigation';

    export let data;

    function loginPage() {
        goto("/login");
    }
    function logoutPage() {
        goto("/logout");
    }
    function signupPage() {
        goto("/signup");
    }
</script>

<svelte:head>
    <title>Sveltekit Example</title>
</svelte:head>
<h1>Sveltekit Session Management Example</h1>

{#if data.user} 
    <p>Logged in as {data.user.username}</p>
    <p><a href="/account">Account details</a></p>
    {#if data?.user.admin}
        <p><a href="/admin">Admin page</a></p>
    {/if}
    <form method="POST" action="logout">
        <button class="btn btn-primary" on:click={logoutPage}>Logout</button>
    </form>
{:else}
    <p>Not logged in</p>
    <p>
        <button class="btn btn-primary" on:click={loginPage}>Login</button>
        &nbsp;
        <button class="btn btn-secondary" on:click={signupPage}>Signup</button>
    </p>
{/if}
