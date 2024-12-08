<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
    /** @type {import('./$types').ActionData} */
    export let form;
</script>
<svelte:head>
    <title>Password Reset</title>
</svelte:head>
<h1>Password Reset</h1>

{#if form?.ok == true}
    <!-- password reset was successful (from the POST action)-->
    <p class="text-slate-900 bg-success p-2 rounded ">Password reset successful</p>
    <p><a href="/">Home</a></p>
{:else if data.tokenValidated == false}
    <!-- Token validation failed -->
    <p class="bg-error p-2 rounded text-slate-900">Error: {data?.error ?? "The token is invalid"}</p>
{:else}
    <!-- token validation was successful - show form -->
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        {#if form?.error} 
            <!-- there was error submitting new password -->
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
        {/if}
        <div class="form-control">
            <label class="label" for="new_password">
            <span class="label-text">New Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="new_password" name="new_password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
            </label>
        </div>

        <div class="form-control">
            <label class="label" for="repeat_password">
            <span class="label-text">Repeat Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="repeat_password" name="repeat_password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Repeat your password"/><br>
            </label>
        </div>

        <button class="btn btn-primary" type="submit">Set Password</button>
    </form>
{/if}
