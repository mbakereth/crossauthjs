<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let factor2 = form?.formData?.factor2 ?? data.allowedFactor2[0].name;
</script>
<svelte:head>
    <title>Create an Account</title>
</svelte:head>
<h1>Create an Account</h1>

{#if form?.emailVerificationRequired}
    <p class="text-slate-900 bg-info p-2 rounded ">Please check your email and
        follow the link we sent to complete registration.
    </p>
    <p><a href="/">Home</a></p>
{:else if form?.factor2Data?.factor2 == "totp"}
    <ConfigureTotp data={data} factor2Data={form?.factor2Data}/>
{:else if form?.success}
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
            <p class="label-text">Second Factor</p>
            {#each data.allowedFactor2 as item }
                <div class="form-control">
                    <span class="align-text-bottom mb-2">
                        <input type="radio" name="factor2" id={"factor2_"+item.name} value={item.name} class="radio align-middle" bind:group={factor2} /> 
                        <span class="align-bottom ml-2 text-sm">{ item.friendlyName }</span>
                    </span>
                </div>
            {/each}
        {/if}

        <button class="btn btn-primary" type="submit">Create</button>
    </form>
{/if}
