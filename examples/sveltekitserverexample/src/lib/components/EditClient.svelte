<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let isAdmin;
    console.log("Edit Client Data", data);
    let redirectUri = form?.formData?.redirectUri ?? data?.client.redirectUri ?? data?.client?.redirectUri.join(" ") ?? "";
    console.log("Redirect uri", redirectUri);   
    let validFlows = form?.formData?.validFlow ?? data?.client.validFlow ?? [];
    console.log("Valid flows", validFlows)
</script>

<svelte:head>
    <title>Update Client</title>
</svelte:head>
<h1>Update OAuth Client
    {#if isAdmin && data.client.user}
        for { data.client.user?.username}
    {/if}
</h1>

{#if form?.success}
    <p class="bg-success p-2 rounded text-slate-900">
        The client was updated.
        {#if form.plaintextSecret}
            Make sure you note down the client secret.  If 
            you lose it, you will have to reset it again.
        {/if} 
    </p>

    <!-- display client -->
    <div class="overflow-x-auto">
        <table class="table">
          <!-- head -->
          <tbody>
            <tr>
                <th>Client ID</th>
                <td>{form.client.clientId}</td>
            </tr>
            <tr>
                {#if isAdmin}
                    <th>User</th>
                    <td>{form.client.user?.username ?? "None"}</td>
                {/if}
            </tr>
            <tr>
                <th>Friendly Name</th>
                <td>{form.client.friendlyName}</td>
            </tr>
            <tr>
                <th>Confidential</th>
                <td>{form.client.confidential? "true" : "false"}</td>
            </tr>
            <tr>
                <th>Client Secret</th>
                <td>{form.plaintextSecret ?? "******"}</td>
            </tr>
            <tr>
                <th>Friendly Name</th>
                <td>
                    {form.client.friendlyName}
                </td>
            </tr>
            <tr>
                <th>Redirect URIs</th>
                <td>
                    {data?.client.redirectUri?.join("<br>") ?? "None"}
                </td>
            </tr>
            <tr>
                <th>Valid Flows</th>
                <td>
                    {#each data?.client.validFlow as item }
                        { data?.validFlowNames[item] }<br>
                    {/each}
                </td>

            </tr>
          </tbody>
        </table>
    </div>
    

{:else}

    <!-- edit the client -->

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
      
        <!-- friendly name -->
        <div class="form-control">
            <label class="label" for="friendlyName">
            <span class="label-text">Friendly Name</span>
            </label>
            <label class="input-group">
                <input type="email" id="friendlyName" name="friendlyName" class="input input-bordered w-full max-w-xs mb-4" placeholder="Client name" value={form?.formData?.friendlyName ?? data?.client?.clientName ?? ""}/><br>
            </label>
        </div>
        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <!-- confidential -->
        <div class="form-control text-left">
            <label class="label cursor-pointer" for="confidential">
                <span>
                    <input type="checkbox" id="confidential" name="confidential" checked={form?.formData?.confidential ?? data?.client.confidential ?? false} class="checkbox align-middle" />
                    <span class="align-middle ml-2 text-left">Confidential</span>
    
                </span>
            </label>
        </div>

        <!-- client secret -->
        <div class="form-control">
            <label class="label" for="clientSecret">
            <span class="label-text">Client ID</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="clientId" name="clientId" class="input input-bordered w-full max-w-xs mb-4" value="******"/>
                &nbsp;
                <span>
                    <input type="checkbox" id="resetSecret" name="resetSecret" checked={false} class="checkbox align-middle" />
                    <span class="align-middle ml-2">Reset secret</span>    
                </span>

            </label>
        </div>

        <!-- redirect URIs -->
        <div class="form-control">
            <label class="label" for="redirectUris">
            <span class="label-text">Redirect URIs (space-separated)</span>
            </label>
            <label class="input-group">
                <input type="text" id="redirectUris" name="redirectUris" class="input input-bordered w-full max-w-xs mb-4" placeholder="eg http://me.com/oauth/redirect" value={redirectUri}/><br>
            </label>
        </div>

        <!-- enabled flows -->
        <h4>Valid Flows</h4>
        {#each data?.validFlows as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="checkbox" name={"flow_"+item} id={"flow_"+item} class="checkbox align-middle" value={item} checked={validFlows.includes(item)}/> 
                    <span class="align-middle ml-2 text-sm">{ data?.validFlowNames[item] }
                    </span>
                </span>
            </div>
        {/each}
        
    </form>

{/if}
