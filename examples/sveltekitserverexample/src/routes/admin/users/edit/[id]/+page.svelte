<script>
    import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let selectedAdmin = form?.formData?.admin != undefined ? (form?.formData ? "1" : "0") : 
        (data.editUser?.admin != undefined ? (data.editUser.admin? "1" : "0") : "0");
    let selectedState = form?.formData.state ?? data.editUser.state;
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
        if (data.editUser?.factor2 == data.allowedFactor2[i].name || (data.allowedFactor2[i].name == "none" && data.editUser?.factor2 == ""))  {
            factor2 = data.allowedFactor2[i].name;
        }
    for (let i=0; i<data.allowedFactor2.length; ++i)
        if (form?.formData.factor2 == data.allowedFactor2[i].name || (data.allowedFactor2[i].name == "none" && form?.formData?.factor2 == ""))  {
            factor2 = data.allowedFactor2[i].name;
        }
</script>
<svelte:head>
    <title>Update Details for {data.editUser.username}</title>
</svelte:head>
<h1>Update Details for {data.editUser.username}</h1>

{#if form?.ok}
    <p class="bg-success p-2 rounded text-slate-900">
        The user's details have been updated.
        {#if form?.info}
        <br>{ form?.info }
        {/if}
    </p>
    <p><a href="/admin/users">Users</a></p>
{:else}
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {/if}
    <form method="POST">

        <!-- password-->
        <div class="form-control">
            <label class="label" for="password">
            <span class="label-text">Password</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="password" name="password" class="input input-bordered w-full max-w-xs mb-4" value="******"/>
                &nbsp;<a href={"/admin/users/changepassword/"+data?.editUser.id}>Change...</a><br>
            </label>
        </div>

        <!-- factor2-->
        {#if data.allowedFactor2.length > 1}
        <p class="label-text">Second Factor</p>
        {#each data.allowedFactor2 as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="radio" name="factor2" id={"factor2_"+item.name} value={item.name} class="radio align-middle" bind:group={factor2} /> 
                    <span class="align-bottom ml-2 text-sm">{ item.friendlyName }
                    </span>
                </span>
            </div>
        {/each}
    {/if}

        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <!-- email -->
        <div class="form-control">
            <label class="label" for="user_email">
            <span class="label-text">Email</span>
            </label>
            <label class="input-group">
                <input type="email" id="user_email" name="user_email" class="input input-bordered w-full max-w-xs mb-4" placeholder="Email" value={form?.formData?.user_email ?? data?.editUser?.email ?? ""}/><br>
            </label>
        </div>

        <!-- Admin-->
        <p class="label-text">Admin</p>
        <input type="hidden" name="type_admin" value="boolean"/> 
        <div class="form-control">
            <span class="align-text-bottom mb-2">
                <input type="radio" name="user_admin" id={"admin_1"} class="radio align-middle" value="1" bind:group={selectedAdmin} /> 
                <span class="align-bottom ml-2 text-sm mr-2">Yes</span>
                <input type="radio" name="user_admin" id={"admin_0"} class="radio align-middle" value="0" bind:group={selectedAdmin} /> 
                <span class="align-bottom ml-2 text-sm">No</span>
            </span>
        </div>

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

        <p><a href={"/admin/oauth/clients?userid="+data.editUser.id}>OAuth Clients</a></p>
        
        <button class="btn btn-primary" type="submit">Update Details</button>
        &nbsp;
        <button type="button" class="btn btn-neutral" on:click={()=>goto("/account")}>Cancel</button>
        &nbsp;
        <button type="button" class="btn btn-error" on:click={()=>goto("/admin/users/delete/"+data.editUser.id)}>Delete User</button>
    </form>
{/if}