<script>
    import { goto } from '$app/navigation';
    export let data;
</script>

<p>Enter the code displayed on the other device</p>

<form method="POST" action="?/userCode">
    <input type="hidden" name="csrfToken" value="{ data.csrfToken }"/>
    <div class="form-control mt-2 ml-3">
        <label class="label" for="otp">
        <span class="label-text">Code</span>
        </label>
        <label class="input-group">
            <input type="text" id="user_code" name="user_code" class="input input-bordered w-full max-w-xs mb-4" placeholder="Code"/><br>
        </label>
    </div>

    <button class="btn btn-primary ml-4" type="submit">Submit</button>
</form>
