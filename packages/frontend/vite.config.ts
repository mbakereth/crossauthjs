/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { join, dirname } from 'path'

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  build: {
    minify: false,
    ssr: false,
    lib: {
      entry: resolve(__dirname, "./src/index.ts"),
      fileName: "index",
      formats: ['es', 'cjs', 'iife'],
      name: "crossauth_frontend"
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
