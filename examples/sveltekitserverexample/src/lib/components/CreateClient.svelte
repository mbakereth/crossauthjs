<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let isAdmin;
    export let back;
    let redirectUri = form?.formData?.redirectUri ?? "";
    let validFlows = form?.formData?.validFlow ?? [];
    let userId = form?.formData?.userId ?? data?.clientUserId;
    let username = form?.formData?.username ?? data?.clientUsername;
</script>

{#if form?.ok}
    <p class="bg-success p-2 rounded text-slate-900">
        The client was created.
        {#if form?.client.confidential}
            Make sure you note down the client secret.  If 
            you lose it, you will have to reset it.
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
                <th>Client Name</th>
                <td>{form.client.clientName}</td>
            </tr>
            {#if form.client.confidential}
                <tr>
                    <th>Client Secret</th>
                    <td>{form.client?.clientSecret}</td>
                </tr>
            {/if}
            <tr>
                <th>Redirect URIs</th>
                <td>
                    {form?.client.redirectUri?.join("<br>") ?? "None"}
                </td>
            </tr>
            <tr>
                <th>Valid Flows</th>
                <td>
                    {#each form?.client.validFlow as item }
                        { data?.validFlowNames[item] }<br>
                    {/each}
                </td>

            </tr>
          </tbody>
        </table>
    </div>
    
    <p><a href={back??"clients"}>Back</a></p>
{:else}

    <!-- edit the client -->

    {#if data?.error} 
        <p class="bg-error p-2 rounded text-slate-900">{data?.error}</p>
    {:else if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">{form?.error}</p>
    {/if}

    <form method="POST">

        <!-- user - ignored if not an admin endpoint-->
        <input readonly type="hidden" id="userId" name="userId" class="input input-bordered w-full max-w-xs mb-4" value={userId ?? ""}/>

         {#if isAdmin}
            <div class="form-control">
                <label class="label" for="username">
                <span class="label-text">User</span>
                </label>
                <label class="input-group">
                    <input readonly type="text" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" value={username ?? "None"}/>
                </label>
            </div>
        {/if}
      
        <!-- client name -->
        <div class="form-control">
            <label class="label" for="clientName">
            <span class="label-text">Client Name</span>
            </label>
            <label class="input-group">
                <input type="text" id="clientName" name="clientName" class="input input-bordered w-full max-w-xs mb-4" placeholder="Client name" value={form?.formData?.clientName ?? ""}/><br>
            </label>
        </div>
        <input type="hidden" name="csrfToken" value={data.csrfToken} />

        <!-- confidential -->
        <div class="form-control text-left">
            <label class="label cursor-pointer" for="confidential">
                <span>
                    <input type="checkbox" id="confidential" name="confidential" checked={form?.formData?.confidential ?? false} class="checkbox align-middle" />
                    <span class="align-middle ml-2 text-left">Confidential</span>
    
                </span>
            </label>
        </div>

        <!-- redirect URIs -->
        <div class="form-control">
            <label class="label" for="redirectUri">
            <span class="label-text">Redirect URIs (space-separated)</span>
            </label>
            <label class="input-group">
                <input type="text" id="redirectUri" name="redirectUri" class="input input-bordered w-full max-w-xs mb-4" placeholder="eg http://me.com/oauth/redirect" value={redirectUri}/><br>
            </label>
        </div>

        <!-- enabled flows -->
        <h4>Valid Flows</h4>
        {#each data?.validFlows as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="checkbox" name={item} id={item} class="checkbox align-middle" value={item} checked={validFlows.includes(item)}/> 
                    <span class="align-middle ml-2 text-sm">{ data?.validFlowNames[item] }
                    </span>
                </span>
            </div>
        {/each}

        <button type="submit" class="btn btn-primary mt-4">Save</button>
        &nbsp;<button type="button" class="btn btn-neutral mt-4"  on:click={() => goto(back??"clients")}>Cancel</button>&nbsp;

    </form>

{/if}
