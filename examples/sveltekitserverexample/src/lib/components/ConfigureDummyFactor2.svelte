<script>
    import { goto } from '$app/navigation';
    export let data;
    export let factor2Data;
</script>

<p class="bg-info text-slate-900 p-2 rounded ">
    Press OK to complete setup
</p>

<form method="POST" action="/configurefactor2">

    <input type="hidden" name="next" value="{ data.next }"/>
    <input type="hidden" name="csrfToken" value="{ factor2Data.csrfToken }"/>
    <input type="hidden" name="otp" value="0000"/>

    <button class="btn btn-primary ml-4" type="submit">OK</button>
</form>
