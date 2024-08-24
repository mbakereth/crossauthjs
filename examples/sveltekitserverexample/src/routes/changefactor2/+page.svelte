<script>
 import ConfigureTotp from '$lib/components/ConfigureTotp.svelte';
 import { goto } from '$app/navigation';
	/** @type {import('./$types').PageData} */
    export let data;
	/** @type {import('./$types').ActionData} */
	export let form;
    let factor2 = form?.formData?.factor2 ?? data.user?.factor2 ?? data.allowedFactor2[0].name;
    let configurable = false;
    if (factor2 == "") factor2 = "none";
    for (let i=0; i<data.allowedFactor2.length; ++i)
        if (factor2 == data.allowedFactor2[i].name)  {
            configurable = data.allowedFactor2[i].configurable;
        }
</script>
<svelte:head>
    <title>Change Two-Factor Authentication</title>
</svelte:head>
<h1>Change Two-Factor Authentication</h1>

{#if form?.ok && !form.factor2Data}
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

    <form method="POST" action="?/change">
        <input type="hidden" name="csrfToken" value={data.csrfToken} />
        <input type="hidden" name="next" value={data?.next ?? "/"} />

        {#if data.allowedFactor2.length > 1}
            <p class="label-text">Second Factor</p>
            {#each data.allowedFactor2 as item }
                <div class="form-control">
                    <span class="align-text-bottom mb-2">
                        <input type="radio" name="factor2" id={"factor2_"+item.name} value={item.name} class="radio align-middle" bind:group={factor2} /> 
                        <span class="align-bottom ml-2 text-sm">{ item.friendlyName }
                            {#if factor2 == item.name && configurable}
                            &nbsp;<a href={null} class="cursor-pointer" 
                                on:click|preventDefault={() => document.forms.namedItem("reconfigureForm")?.submit()}>Reconfigure</a>
                            {/if}
                        </span>
                    </span>
                </div>
            {/each}
        {/if}


        <button class="btn btn-primary" type="submit">Change</button>&nbsp;
        <button type="button" class="btn btn-neutral" on:click={() => goto("/account")}>Cancel</button>
    </form>

    <form method="POST" action="?/reconfigure" id = "reconfigureForm">
    </form>
{/if}