/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
//import pinoplugin from 'esbuild-plugin-pino';
import { join, dirname } from 'path'

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  /*esbuild: {
	minifyIdentifiers: false,
	keepNames: true,
  },*/
  build: {
      ssr: false,
      minify: 'esbuild',
      lib: {
        entry: resolve(__dirname, "./src/index.ts"),
        fileName: "index",
        formats: ['es', 'cjs', 'iife'],
        name: "crossauth_common"
        },
    /*watch: {
      // https://rollupjs.org/configuration-options/#watch
    },*/
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: [],
  },
},
  plugins: [
    dts(),
    //pinoplugin({ transports: ['pino-pretty'] })
  ],
  test: {
    // ...
  },
  });
