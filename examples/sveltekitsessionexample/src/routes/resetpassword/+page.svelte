<script>
    /** @type {import('./$types').PageData} */
    export let data;
    /** @type {import('./$types').ActionData} */
    export let form;
</script>

<svelte:head>
    <title>Password Reset</title>
</svelte:head>
<h1>Password Reset</h1>

{#if form?.success}
<p class="bg-info p-2 rounded text-slate-900">
    Please click on the link in the email we sent you.
</p>

{:else}
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        {#if form?.error} 
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
        {:else if data?.required}
        <p class="bg-info p-2 rounded text-slate-900">You are required to reset your password</p>
        {/if}
        <div class="form-control">
            <label class="label" for="email">
            <span class="label-text">Email address</span>
            </label>
            <label class="input-group">
                <input type="email" id="email" name="email" class="input input-bordered w-full max-w-xs mb-4" placeholder="eg joe@bloggs.com" value={form?.formData?.username ?? ''}/><br>
            </label>
        </div>

        <button class="btn btn-primary" type="submit">Reset Password</button>
    </form>
{/if}
