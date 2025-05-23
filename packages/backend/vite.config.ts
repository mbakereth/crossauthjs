/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import { resolve } from 'path';
/// <reference types="vitest" />
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { join, dirname } from 'path'

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  /*esbuild: {
    minifyIdentifiers: false,
    keepNames: true,
  },*/
  build: {
    ssr: true,
    minify: 'esbuild',
    lib: {
      entry: resolve(__dirname, "./src/index.ts"),
      fileName: "server",
      formats: ['es', 'cjs']
      },
    /*watch: {
      // https://rollupjs.org/configuration-options/#watch
    },*/
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['.env', 'prisma', '@prisma/client', 'express', '@types/express', 'nunjucks', '@types/nunjucks', 'node:crypto', 'crypto', 'fastify', '@fastify/cookie', '@fastify/view', '@fastify/formbody', 'otplib',  'qrcode', '@types/qrcode', 'twilio', '@types/twilio', 'pg'],
    },
  },
  plugins: [
    dts(),
    //pinoplugin({ transports: ['pino-pretty'] })
  ],
  resolve: {
    preserveSymlinks: true,
  },
  test: {
    globals: true,
		environment: 'happy-dom',
    // ...
  },
  });
