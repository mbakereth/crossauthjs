//import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import dts from 'vite-plugin-dts';

export default defineConfig({
	plugins: [
		dts(),
		//sveltekit(),
	],
	test: {
		include: ['src/**/*.{test,spec}.{js,ts}']
	},
  resolve: {
    preserveSymlinks: true,
  }

});
