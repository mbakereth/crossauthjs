//import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import { sveltekit } from '@sveltejs/kit/vite';
import dts from 'vite-plugin-dts';
import { resolve } from 'path';

export default defineConfig({
	build: {
		rollupOptions: {
		  // make sure to externalize deps that shouldn't be bundled
		  // into your library
		  external: ['.env', '.env.unittest', 'prisma', '@prisma/client', 'node:crypto', 'crypto', '@sveltejs/kit'],
		},
	  },
	plugins: [
		dts(),
		sveltekit(),
	],
	test: {
		include: ['src/**/*.{test,spec}.{js,ts}'],
		globals: true,
		environment: 'happy-dom',
	},
  resolve: {
    preserveSymlinks: true,
  }

});
