<script>
    import { goto } from '$app/navigation';
    export let data;
    export let form;
    export let back;
</script>

<svelte:head>
    <title>Delete Client</title>
</svelte:head>
<h1>Delete OAuth Client</h1>

{#if form?.success}
    <p class="bg-success p-2 rounded text-slate-900">
        The client was deleted.
    </p>
    <p><a href={back??".."}>Back</a></p>
{:else if (form?.error)}
    <p class="bg-error p-2 rounded text-slate-900">
        {form.error}.
    </p>
    <p><a href={back??".."}>Back</a></p>
{:else if (data?.error)}
    <p class="bg-error p-2 rounded text-slate-900">
        {data.error}.
    </p>
    <p><a href={back??".."}>Back</a></p>
{:else}
    <form method="POST">
        <p class="bg-warning p-2 rounded text-slate-900">
            Are you sure you want to delete client {data?.client?.clientName}?
        </p>
        <button type="submit" class="btn btn-error mt-4">Delete</button>
        &nbsp;<button type="button" class="btn btn-neutral mt-4"  on:click={() => goto(back??"..")}>Cancel</button>&nbsp;
    </form>
{/if}
