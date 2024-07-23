<script>
    import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let factor2 = form?.formData?.factor2 ?? "";
    /*onMount(() => {
        if (form?.success) {
            goto("/");
        }
    });*/
</script>
<svelte:head>
    <title>Create an Account</title>
</svelte:head>
<h1>Create an Account</h1>

{#if form?.success}
    <p class="text-slate-900 bg-success p-2 rounded ">User created</p>
    <p><a href="/">Home</a></p>
{:else}
    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        {#if form?.error} 
            <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
        {/if}
        <div class="form-control">
            <label class="label" for="username">
            <span class="label-text">Username</span>
            </label>
            <label class="input-group">
                <input type="username" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" placeholder="eg bloggsj" value={form?.formData?.username ?? ''}/><br>
            </label>
        </div>

        <div class="form-control">
            <label class="label" for="password">
            <span class="label-text">Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
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

        <div class="form-control">
            <label class="label" for="user_email">
            <span class="label-text">Email</span>
            </label>
            <label class="input-group">
                <input type="email" id="user_email" name="user_email" class="input input-bordered w-full max-w-xs mb-4" placeholder="bloggsj@joebloggs.com" value={form?.formData?.user_email ?? ''}/><br>
            </label>
        </div>

        <div class="form-control">
            <label class="label" for="user_phone">
            <span class="label-text">Email</span>
            </label>
            <label class="input-group">
                <input type="text" id="user_phone" name="user_phone" class="input input-bordered w-full max-w-xs mb-4" placeholder="+12 3456 7890   " value={form?.formData?.user_phone ?? ''}/><br>
            </label>
        </div>

        {#if data.allowedFactor2.length > 1}
            <div class="form-control">
                <label class="label" for="factor2">
                    <span class="label-text">Email</span>
                </label>
                {#each data.allowedFactor2 as item }
                    <input type="radio" name="factor2" id={"factor2_"+item.name} value={item.name} class="radio" bind:group={factor2} /> 
                    <label for="factor2_{item.name}">{ item.friendlyName }</label>
                {/each}
            </div>
        {/if}

        <button class="btn btn-primary" type="submit">Create</button>
    </form>
{/if}
