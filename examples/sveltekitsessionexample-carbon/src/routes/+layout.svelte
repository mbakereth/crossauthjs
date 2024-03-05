<script>
    import { browser } from '$app/environment';
    import "carbon-components-svelte/css/g90.css";
    import { 
        Content,
    } from 'carbon-components-svelte'

</script>  
<Content>
    <slot/>

</Content>

<style>
    :global(body) {
        margin-top: 2ex;
        margin-left: 4ex;
        margin-right: 4ex;
        font-size: 12pt;        
    }
    /*:global(.darkmode label) {
        color: #bbb;
    }*/
    :global(.bx--checkbox-label::before, .bx--checkbox-label::after) {
        outline: 2px solid transparent !important; 
        outline-offset: 2px !important;
    }
    :global(:focus:not(:focus-visible)) {
        outline: 2px solid transparent !important; 
        outline-offset: 2px !important;
    }

</style>