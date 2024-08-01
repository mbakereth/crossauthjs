<script>
    import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let factor2 = "None";
    for (let i=0; i<data.allowedFactor2.length; ++i)
        if (data.user?.factor2 == data.allowedFactor2[i].name)  {
            factor2 = data.allowedFactor2[i].friendlyName;
        }
    for (let i=0; i<data.allowedFactor2.length; ++i)
        if (form?.formData.factor2 == data.allowedFactor2[i].name)  {
            factor2 = data.allowedFactor2[i].friendlyName;
        }
</script>
<svelte:head>
    <title>Update your Details</title>
</svelte:head>
<h1>Update your Details</h1>

{#if form?.success}
    {#if form?.emailVerificationNeeded}
        <p class="bg-success p-2 rounded text-slate-900">
            Please click on the link we emailed you to finish updating your details.
        </p>
    {:else}
        <p class="bg-success p-2 rounded text-slate-900">Your details have been updated</p>
    {/if}
    <p><a href="/account">Your Account</a></p>
{:else}
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {/if}
    <form method="POST">
        <div class="form-control">
            <label class="label" for="password">
            <span class="label-text">Password</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" value="******"/>
                &nbsp;<a href="/changepassword">Change...</a><br>
            </label>
        </div>

        {#if data.allowedFactor2.length > 1}
            <div class="form-control">
                <label class="label" for="factor2">
                <span class="label-text">Two-Factor Authentication</span>
                </label>
                <label class="input-group">
                    <input readonly type="text" id="factor2" name="factor2" class="input input-bordered w-full max-w-xs mb-4" value={factor2}/>
                    &nbsp;<a href="/changefactor2">Change...</a><br>
                </label>
                </div>
        {/if}

        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <div class="form-control">
            <label class="label" for="user_email">
            <span class="label-text">Email</span>
            </label>
            <label class="input-group">
                <input type="email" id="user_email" name="user_email" class="input input-bordered w-full max-w-xs mb-4" placeholder="Email" value={form?.formData?.user_email ?? data?.user?.email ?? ""}/><br>
            </label>
        </div>

        <button class="btn btn-primary" type="submit">Update Details</button>
        &nbsp;
        <button type="button" class="btn btn-neutral" on:click={()=>goto("/account")}>Cancel</button>
    </form>
{/if}