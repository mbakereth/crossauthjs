import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import basicSsl from '@vitejs/plugin-basic-ssl'


export default defineConfig({
	plugins: [sveltekit(), basicSsl()],
	test: {
		include: ['src/**/*.{test,spec}.{js,ts}']
	},
  build: {
    rollupOptions: {
      external: ["fsevents"]
    }
  },
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {}
  },

});
