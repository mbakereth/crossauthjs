<script>
    export let data;
</script>
<svelte:head>
    <title>Your Account</title>
</svelte:head>
<h1>Your Account</h1>

<h4>Welcome {data.user?.username}</h4>

<p><a href="/changepassword">Change password</a></p>
<p><a href="/updateuser">Update user details</a></p>
<p><a href="/deleteuser">Delete your account</a></p>
<p><a href="/">Home</a></p>
