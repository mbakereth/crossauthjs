/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

const config = {
  index: {
    entry: resolve(__dirname, "./src/index.ts"),
    fileName: "index",
    formats: ['es', 'cjs']
  },
  client: {
    entry: resolve(__dirname, "./src/client.ts"),
    fileName: "client",
    formats: ['es', 'cjs']
  },
  server: {
    entry: resolve(__dirname, "./src/server.ts"),
    fileName: "server",
    formats: ['es', 'cjs']
  },
  indexiife: {
    entry: resolve(__dirname, "./src/index.ts"),
    fileName: "index",
    name: "crossauth",
    formats: ['iife']
  },
  clientiife: {
    entry: resolve(__dirname, "./src/client.ts"),
    fileName: "client",
    name: "crossauth_client",
    formats: ['iife']
  },
};

if (process.env.LIB_NAME === undefined) {
  throw new Error('LIB_NAME is not defined or is not valid');
}
const currentConfig = config[process.env.LIB_NAME];

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  build: {
    lib: {
      ...currentConfig,
    },
    /*watch: {
      // https://rollupjs.org/configuration-options/#watch
    },*/
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['prisma', '@prisma/client', 'express', 'node:crypto' ],
      output: {
        // Provide global variables to use in the UMD build
        // for externalized deps
        globals: {
          vue: 'Vue',
        },
      },
    },
  },
  plugins: [
    dts(),
  ],
  test: {
    // ...
  },
});
