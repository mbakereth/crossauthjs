<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let factor2 = form?.formData?.factor2 ?? data.user?.factor2 ?? data.allowedFactor2[0].name;
    if (factor2 == "") factor2 = "none";

    function cancel() {
        goto("/account");
    }
</script>
<svelte:head>
    <title>Change Two-Factor Authentication</title>
</svelte:head>
<h1>Change Two-Factor Authentication</h1>

{#if form?.success && !form.factor2Data}
    <p class="bg-success p-2 rounded text-slate-900">Your two-factor authentication has been updated</p>
    <p><a href="/account">Your Account</a></p>
{:else if form?.factor2Data?.factor2 == "totp"}
    <ConfigureTotp data={data} factor2Data={form?.factor2Data}/>
{:else}
    {#if form?.error} 
        <p class="bg-error p-2 rounded text-slate-900">Error: {form?.error}</p>
    {:else if data?.required}
        <p>You are required to change your two-factor authentication configuration.</p>
    {/if}

    <form method="POST">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />

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


        <button class="btn btn-primary" type="submit">Change</button>&nbsp;
        <button type="button" class="btn btn-secondary" on:click={cancel}>Cancel</button>
    </form>
{/if}