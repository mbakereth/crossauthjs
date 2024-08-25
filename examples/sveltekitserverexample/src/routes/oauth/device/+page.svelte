<script>
    import DeviceAuthorizeScope from '$lib/components/DeviceAuthorizeScope.svelte'
    import DeviceRequestUserCode from '$lib/components/DeviceRequestUserCode.svelte'
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    console.log(data);
    $: cancelled = false;
</script>

<svelte:head>
    <title>Authorize</title>
</svelte:head>
<h1>Authorize Your Account</h1>

{#if cancelled} 
    <p class="bg-info p-2 rounded text-slate-900">Authorization cancelled</p>
{:else if form?.ok == undefined}
    <!-- form hasn't been submitted yet -->
    {#if data?.error == "access_denied"}
        <p class="bg-error p-2 rounded text-slate-900">The code is not valid</p>
    {:else if data?.error == "expired_token"}
        <p class="bg-error p-2 rounded text-slate-900">The code has expired</p>
    {:else if data?.error}
        <p class="bg-error p-2 rounded text-slate-900">{data?.error_description ?? "There was an error"}</p>
    {:else if data?.completed}
        <p class="bg-success p-2 rounded text-slate-900">Code successfully submitted.  Please return to the other device.</p>
    {:else if data?.authorizationNeeded}
        <!-- ask the user for authorization-->
        {#if form?.error}
            <!-- there was an error during form submission -->
            <p class="bg-error p-2 rounded text-slate-900">
                {form?.error_description ?? "An unknown error occurred"}
            </p>
        {/if}
        <DeviceAuthorizeScope data={data} form={form} cancelled={cancelled}/>
    {:else}
        <!-- prompt the user for the user code-->
        <DeviceRequestUserCode data={data} />
    {/if}

{:else if form?.error && form?.retryAllowed == false}
    <!-- form has been submitted and there was a fatal error -->
    <p class="bg-error p-2 rounded text-slate-900">
        {form?.error_description ?? "An error has occurred"}
    </p>
{:else}
    <!-- form has been submitted without a fatal error-->
    {#if form?.error}
        <!-- non fatal error -->
        <p class="bg-error p-2 rounded text-slate-900">
            {form?.error_description ?? "An error has occurred.  Please try again"}
        </p>
    {/if}
    {#if form?.completed}
        <p class="bg-success p-2 rounded text-slate-900">Code successfully submitted.  Please return to the other device.</p>
        {:else if data?.authorizationNeeded}
        <!-- ask the user for authorization-->
        {#if form?.error}
            <!-- there was an error during form submission -->
            <p class="bg-error p-2 rounded text-slate-900">
                {form?.error_description ?? "An unknown error occurred"}
            </p>
        {/if}
        <DeviceAuthorizeScope data={data} form={form} cancelled={cancelled}/>
    {:else}
        <!-- prompt the user for the user code-->
        <DeviceRequestUserCode data={data} />
    {/if}
{/if}
