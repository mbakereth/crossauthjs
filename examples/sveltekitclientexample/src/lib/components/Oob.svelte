<script>
    import { goto } from '$app/navigation';
    export let data;
    export let error;
</script>
<h2>Enter Your One-Time Password</h2>

{#if error}
    <p class="bg-error p-2 rounded text-slate-900">{error}</p>
{/if}

<p>Enter the code we just emailed you.</p>

    <input type="hidden" name="csrfToken" value="{ data.csrfToken }"/>
    <div class="form-control mt-2 ml-3">
        <label class="label" for="otp">
        <span class="label-text">Code</span>
        </label>
        <label class="input-group">
            <input type="password" id="oob" name="otp" class="input input-bordered w-full max-w-xs mb-4" placeholder="Code"/><br>
        </label>
    </div>

    <button class="btn btn-primary ml-4" type="submit">Submit</button>
