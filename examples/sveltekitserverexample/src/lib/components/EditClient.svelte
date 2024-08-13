<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let isAdmin;
</script>

<svelte:head>
    <title>Clients</title>
</svelte:head>
<h1>Edit OAuth Client
    {#if isAdmin && data.client.user}
    for {{ data.client.user?.username}}
    {/if}
</h1>

{#if form?.success}
<p class="bg-success p-2 rounded text-slate-900">Client updated</p>
{:else}
    {#if data?.error} 
        <p class="bg-error p-2 rounded text-slate-900">{data?.error}</p>
    {:else if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">{form?.error}</p>
    {/if}

    <form method="POST">

        <!-- client id-->
        <div class="form-control">
            <label class="label" for="clientId">
            <span class="label-text">Client ID</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="clientId" name="clientId" class="input input-bordered w-full max-w-xs mb-4" value="{data?.client.clientId}"/>
            </label>
        </div>

        <!-- user -->
         {#if isAdmin}
            <div class="form-control">
                <label class="label" for="username">
                <span class="label-text">Username</span>
                </label>
                <label class="input-group">
                    <input readonly type="text" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" value="{data?.client.user?.username} ?? None"/>
                </label>
            </div>
        {/if}
        
        <!-- client secret -->
        <div class="form-control">
            <label class="label" for="clientSecret">
            <span class="label-text">Client ID</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="clientId" name="clientId" class="input input-bordered w-full max-w-xs mb-4" value="******"/>
                &nbsp;<a href={"../resetsecret/"+data?.client.clientId}>Reset...</a><br>
            </label>
        </div>

        <!-- friendly name -->
        <div class="form-control">
            <label class="label" for="friendlyName">
            <span class="label-text">Friendly Name</span>
            </label>
            <label class="input-group">
                <input type="email" id="friendlyName" name="friendlyName" class="input input-bordered w-full max-w-xs mb-4" placeholder="Client name" value={form?.formData?.friendlyName ?? data?.client?.friendlyName ?? ""}/><br>
            </label>
        </div>
        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <!-- confidential -->
        <div class="form-control">
            <label class="label cursor-pointer" for="confidential">
                <input type="checkbox" id="confidential" name="confidential" checked={formData.confidential ?? data?.client.confidential ?? false} class="checkbox" />
                <span class="align-bottom ml-2">Confidential</span>
            </label>
        </div>


        <!-- redirect URIs -->
        <div class="form-control">
            <label class="label" for="redirectUris">
            <span class="label-text">Redirect URIs (space-separated)</span>
            </label>
            <label class="input-group">
                <input type="email" id="redirectUris" name="redirectUris" class="input input-bordered w-full max-w-xs mb-4" placeholder="http://me.com/oauth/redirect" value={form?.formData?.redirectUris ?? data?.client?.redirectUris ?? ""}/><br>
            </label>
        </div>

        <!-- enabled flows -->
        <p class="label-text">State</p>
        {#each data?.validFlows as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="checkbox" name={"flow_"+item.name} id={"flow_"+item.name} class="radio align-middle" value={item.friendlyName} /> 
                    <span class="align-bottom ml-2 text-sm">{ item.friendlyName }
                    </span>
                </span>
            </div>
        {/each}
        
    </form>

{/if}
