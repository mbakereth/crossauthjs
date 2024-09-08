//import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vitest/config';
import dts from 'vite-plugin-dts';
import { resolve } from 'path';

export default defineConfig({
	build: {
		ssr: true,
                minify: 'esbuild',
		lib: {
		  entry: resolve(__dirname, "./src/index.ts"),
		  fileName: "index",
		  formats: ['es', 'cjs']
		  },
		/*watch: {
		  // https://rollupjs.org/configuration-options/#watch
		},*/
		rollupOptions: {
		  // make sure to externalize deps that shouldn't be bundled
		  // into your library
		  external: ['.env', '.env.unittest', 'prisma', '@prisma/client', 'node:crypto', 'crypto', ],
		},
	  },
	plugins: [
		dts(),
		//sveltekit(),
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
