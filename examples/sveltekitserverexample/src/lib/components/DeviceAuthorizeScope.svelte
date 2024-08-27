<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let cancelled;
    let authorizationNeeded = form?.authorizationNeeded ?? data?.authorizationNeeded;
</script>

<form method="POST" action="?/authorize">
    <input type="hidden" name="csrfToken" value={data.csrfToken} />
    {#if (authorizationNeeded.scopes && authorizationNeeded.scopes.length > 0)}
        <p class="bg-warning p-2 rounded text-slate-900">
            Do you agree to authorize <b>{authorizationNeeded.client_name}</b>
            to access your account with the following scopes?
        </p>
        <ul class="ml-8 list-disc">
            {#each authorizationNeeded.scopes as scope}
                <li>{scope}</li>
            {/each}
        </ul>
    {:else}
        <p class="bg-warning p-2 rounded text-slate-900">
            Do you agree to authorize <b>{authorizationNeeded.client_name}</b>
            to access your account?
        </p>
    {/if}

    <input type="hidden" name="authorized" value="true"/>
    <input type="hidden" name="client_id" value={authorizationNeeded?.client_id}/>
    <input type="hidden" name="user_code" value={form?.user_code ?? data?.user_code}/>
    {#if authorizationNeeded?.scope}
        <input type="hidden" name="scope" value={authorizationNeeded?.scope}/>
    {/if}
    <p>
        <button class="btn btn-primary" type="submit">Authorize</button>&nbsp;
        <button class="btn btn-neutral" type="button" on:click={() => {cancelled = true}}>Cancel</button>
    </p>
</form>
