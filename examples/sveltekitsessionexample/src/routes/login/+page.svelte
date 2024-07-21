<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    /*onMount(() => {
        if (form?.success) {
            goto("/");
        }
    });*/
</script>
<svelte:head>
    <title>Login</title>
</svelte:head>
<h1>Login</h1>

<form method="POST">
    <input type="hidden" name="csrfToken" value={data.csrfToken} />
    <input type="hidden" name="next" value={data.next ?? "/"} />
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {/if}
    <input type="username" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" placeholder="Username" value={form?.formData?.username ?? ''}/><br>

    <input type="password" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"><br>

    <button class="btn btn-primary" type="submit">Log in</button>
    <p class="mt-3 mb-3 text-muted"><a href="/passwordreset">Forgot Password</a></p> 
</form>

