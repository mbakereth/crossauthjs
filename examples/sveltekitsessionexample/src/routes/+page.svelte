<script lang="ts">
    import { Form, TextInput, PasswordInput, Button, Link, Checkbox, Tabs, Tab, TabContent } from 'carbon-components-svelte'

    let checkbox : HTMLInputElement;

</script>

<h1>Sign up</h1>
<div id="inputs">
    <Form method="post">
        <TextInput name="username" labelText="User name" placeholder="Enter user name..." /><br>
        <PasswordInput name="password" labelText="Password" placeholder="Enter password..." /><br>
        <Button type="submit">Sign Up</Button>
    </Form>    
</div><br>
<Checkbox bind:ref={checkbox} on:click={() => checkbox.blur()} labelText="Label text" />
<Link href="/">Login</Link>

<Tabs>
    <Tab label="Tab label 1" />
    <Tab label="Tab label 2" />
    <Tab label="Tab label 3" />
    <svelte:fragment slot="content">
      <TabContent>Content 1</TabContent>
      <TabContent>Content 2</TabContent>
      <TabContent>Content 3</TabContent>
    </svelte:fragment>
  </Tabs>
  
  
<style>
    #inputs {
        margin-top: 1ex;
        max-width: 400px;
    }
</style>
