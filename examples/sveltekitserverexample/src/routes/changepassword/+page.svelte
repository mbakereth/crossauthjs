<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
</script>
<svelte:head>
    <title>Change Your Password</title>
</svelte:head>
<h1>Change Your Password</h1>

{#if form?.ok}
    <p class="bg-success p-2 rounded text-slate-900">Your password has been changed</p>
    <p><a href="/account">Your Account</a></p>
{:else}
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {:else if data?.required}
    <p class="bg-info p-2 rounded text-slate-900">You are required to change your password</p>
    {/if}
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <div class="form-control">
            <label class="label" for="old_password">
            <span class="label-text">Old Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="old_password" name="old_password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
            </label>
        </div>

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
                <input type="password" id="repeat_password" name="repeat_password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
            </label>
        </div>


        <button class="btn btn-primary" type="submit">Change Password</button>
    </form>
{/if}