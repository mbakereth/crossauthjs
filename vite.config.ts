/// <reference types="vitest" />
// Configure Vitest (https://vitest.dev/config/)
import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
//import pinoplugin from 'esbuild-plugin-pino';
import { join, dirname } from 'path'

const libConfig = {
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

const buildConfig = {
  index: {
    ssr: true,
  },
  client: {
  },
  server: {
    ssr: true,
  },
  indexiife: {
  },
  clientiife: {
  },
};

if (process.env.LIB_NAME === undefined) {
  throw new Error('LIB_NAME is not defined or is not valid');
}
const currentLibConfig = libConfig[process.env.LIB_NAME];
const currentBuildConfig = buildConfig[process.env.LIB_NAME];

/*const pathToPino = resolve('./node_modules/pino')
console.log(pathToPino)
  // @ts-ignore
  globalThis.__bundlerPathsOverrides = {
    'pino-worker': pathToPino+'/lib/worker.js',
    'pino-pipeline-worker': pathToPino+'/lib/worker-pipeline.js',
    'thread-stream-worker': pathToPino+'/../thread-stream/lib/worker.js',
    'pino/file': pathToPino+'/file.ts',
}
globalThis.__bundlerPathsOverrides['pino-pretty'] =  pathToPino+'/../pino-pretty/index.js'
globalThis.__bundlerPathsOverrides['pino-opentelemetry-transport'] = pathToPino+'/../pino-opentelemetry-transport/pino-opentelemetry-transport.js'
*/

// https://vitejs.dev/guide/build.html#library-mode
export default defineConfig({
  build: {
    ...currentBuildConfig,
    lib: {
      ...currentLibConfig,
    },
    /*watch: {
      // https://rollupjs.org/configuration-options/#watch
    },*/
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['prisma', '@prisma/client', 'express', '@types/express', 'nunjucks', '@types/nunjucks', 'node:crypto', 'crypto', 'fastify', '@fastify/cookie', '@fastify/view', '@fastify/formbody' ],
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
