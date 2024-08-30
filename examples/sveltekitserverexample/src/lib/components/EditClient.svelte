<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let isAdmin;
    export let back;
    let redirect_uri = form?.formData?.redirect_uri ?? data?.client?.redirect_uri?.join(" ") ?? "";
    let validFlows = form?.formData?.valid_flow ?? data?.client?.valid_flow ?? [];
    let confidential = form?.formData?.confidential ?? data?.client?.confidential ?? false;
    let haveClientSecret = data?.client.client_secret && data?.client.client_secret.length > 0;
</script>

{#if form?.ok}
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
                <td>{form.client.client_id}</td>
            </tr>
            <tr>
                {#if isAdmin}
                    <th>User</th>
                    <td>{form.client.user?.username ?? "None"}</td>
                {/if}
            </tr>
            <tr>
                <th>Client Name</th>
                <td>{form.client.client_name}</td>
            </tr>
            <tr>
                <th>Confidential</th>
                <td>{form.client.confidential? "true" : "false"}</td>
            </tr>
            {#if form.client.confidential}
                <tr>
                    <th>Client Secret</th>
                    <td>{form.plaintextSecret ?? "******"}</td>
                </tr>
            {/if}
            <tr>
                <th>Redirect URIs</th>
                <td>
                    {form?.client.redirect_uri?.join("<br>") ?? "None"}
                </td>
            </tr>
            <tr>
                <th>Valid Flows</th>
                <td>
                    {#each form?.client.valid_flow as item }
                        { data?.valid_flowNames[item] }<br>
                    {/each}
                </td>

            </tr>
          </tbody>
        </table>
    </div>
    
    <p><a href={back??""}>Back to clients</a></p>
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
            <label class="label" for="client_id">
            <span class="label-text">Client ID</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="client_id" name="client_id" class="input input-bordered w-full max-w-xs mb-4" value="{data?.client_id}"/>
            </label>
        </div>

        <!-- user - ignored if not an admin endpoint-->
        <input readonly type="hidden" id="userid" name="userid" class="input input-bordered w-full max-w-xs mb-4" value={data?.client.userid ?? ""}/>

         {#if isAdmin}
            <div class="form-control">
                <label class="label" for="username">
                <span class="label-text">User</span>
                </label>
                <label class="input-group">
                    <input readonly type="text" id="username" name="username" class="input input-bordered w-full max-w-xs mb-4" value={data?.clientUsername ?? "None"}/>
                </label>
            </div>
        {/if}
      
        <!-- client name -->
        <div class="form-control">
            <label class="label" for="client_name">
            <span class="label-text">Client Name</span>
            </label>
            <label class="input-group">
                <input type="text" id="client_name" name="client_name" class="input input-bordered w-full max-w-xs mb-4" placeholder="Client name" value={form?.formData?.client_name ?? data?.client?.client_name ?? ""}/><br>
            </label>
        </div>
        <input type="hidden" name="csrfToken" value={data.csrfToken??""} />

        <!-- confidential -->
        <div class="form-control text-left">
            <label class="label cursor-pointer" for="confidential">
                <span>
                    <input type="checkbox" id="confidential" name="confidential" bind:checked={confidential}  class="checkbox align-middle" />
                    <span class="align-middle ml-2 text-left">Confidential</span>
    
                </span>
            </label>
        </div>

        <!-- client secret -->
        {#if confidential}
        <div class="form-control">
            <label class="label" for="client_secret">
            <span class="label-text">Client Seceret</span>
            </label>
            <label class="input-group">
                <input readonly type="text" id="client_id" name="client_id" class="input input-bordered w-full max-w-xs mb-4" value={haveClientSecret? "******" : "None set"}/>
                &nbsp;
                <span>
                    <input type="checkbox" id="resetSecret" name="resetSecret" checked={false} class="checkbox align-middle" />
                    <span class="align-middle ml-2">Reset secret</span>    
                </span>

            </label>
        </div>
        {/if}

        <!-- redirect URIs -->
        <div class="form-control">
            <label class="label" for="redirect_uri">
            <span class="label-text">Redirect URIs (space-separated)</span>
            </label>
            <label class="input-group">
                <input type="text" id="redirect_uri" name="redirect_uri" class="input input-bordered w-full max-w-xs mb-4" placeholder="eg http://me.com/oauth/redirect" value={redirect_uri}/><br>
            </label>
        </div>

        <!-- enabled flows -->
        <h4>Valid Flows</h4>
        {#each data?.validFlows as item }
            <div class="form-control">
                <span class="align-text-bottom mb-2">
                    <input type="checkbox" name={item} id={item} class="checkbox align-middle" value={item} checked={validFlows.includes(item)}/> 
                    <span class="align-middle ml-2 text-sm">{ data?.valid_flowNames[item] }
                    </span>
                </span>
            </div>
        {/each}

        <button type="submit" class="btn btn-primary mt-4">Save</button>
        &nbsp;<button type="button" class="btn btn-neutral mt-4"  on:click={() => goto(back??"..")}>Cancel</button>&nbsp;
        &nbsp;<button type="button" class="btn btn-error mt-4"  on:click={() => goto("../delete/"+data?.client_id)}>Delete</button>&nbsp;

    </form>

{/if}
