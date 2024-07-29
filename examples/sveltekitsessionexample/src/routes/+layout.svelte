<script>
    import "tailwindcss/tailwind.css";
  </script>
  
<div class="m-8">
    <slot />
</div>
  
<style lang="postcss">
:global(h1, h2, h3, h4, h5, h6) {
  @apply leading-tight mt-3 mb-6;
}

:global(h1) {
  @apply text-4xl;
}

:global(h2) {
  @apply text-3xl;
}

:global(h3) {
  @apply text-2xl;
}

:global(h4) {
  @apply text-xl;
}

:global(p) {
  @apply mt-2 mb-2;
}

:global(a) {
  @apply text-primary;
}

</style>