<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
    import { onMount } from 'svelte';
    import Layout from '../../../+layout.svelte';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let selectedState = form?.user?.state ?? form?.formData?.state ?? "active";
    let states = [
        {name: "active", friendlyName: "Active"},
        {name: "factor2resetneeded", friendlyName: "Factor 2 Reset Needed"},
        {name: "passwordchangeneeded", friendlyName: "Password Change Needed"},
        {name: "passwordresetneeded", friendlyName: "Password Reset Needed"},
        {name: "passwordandfactor2resetneeded", friendlyName: "Password and Factor 2 Reset Needed"},
        {name: "inactive", friendlyName: "Inactive"},
    ];
    let factor2 = "none";
    for (let i=0; i<data.allowedFactor2.length; ++i)
        if (form?.formData.factor2 == data.allowedFactor2[i].name || (data.allowedFactor2[i].name == "none" && form?.formData?.factor2 == ""))  {
            factor2 = data.allowedFactor2[i].name;
        }
</script>
<svelte:head>
    <title>Create an Account</title>
</svelte:head>
<h1>Create an Account</h1>

{#if form?.success}
    <p class="text-slate-900 bg-success p-2 rounded ">
        User created.
        {#if form?.user?.state == "passwordresetneeded"}
            User will have to reset their password and has been sent an email.
        {:else if form?.user?.state == "factor2resetneeded"}
            User will have to configure 2FA on login.
        {:else if form?.user.state == "passwordandfactor2resetneeded"}
            User will have to reset their password and has been sent an email.
            After that they will have to configure 2FA on login.
        {/if}
    </p>
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

        <!-- password -->
        <div class="form-control">
            <label class="label" for="password">
            <span class="label-text">Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Password"/><br>
            </label>
        </div>

        <!-- repeat password -->
        <div class="form-control">
            <label class="label" for="repeat_password">
            <span class="label-text">Repeat Password</span>
            </label>
            <label class="input-group">
                <input type="password" id="repeat_password" name="repeat_password" class="input input-bordered w-full max-w-xs mb-4" placeholder="Repeat your password"/><br>
            </label>
        </div>

        <!-- email -->
        <div class="form-control">
            <label class="label" for="user_email">
            <span class="label-text">Email</span>
            </label>
            <label class="input-group">
                <input type="email" id="user_email" name="user_email" class="input input-bordered w-full max-w-xs mb-4" placeholder="joe@bloggs.com" value={form?.formData?.user_email ?? ''}/><br>
            </label>
        </div>

        <!-- factor2 -->
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

        <!-- state-->
        <p class="label-text">State</p>
        {#each states as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="radio" name="state" id={"state_"+item.name} class="radio align-middle" value={item.name} bind:group={selectedState} /> 
                    <span class="align-bottom ml-2 text-sm">{ item.friendlyName }
                    </span>
                </span>
            </div>
        {/each}
        

        <button class="btn btn-primary" type="submit">Create</button>&nbsp;
        <button class="btn btn-secondary" type="button" on:click={()=>goto("/admin/users")}>Cancel</button>
    </form>
{/if}
