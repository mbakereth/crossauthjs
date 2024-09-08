#!/bin/bash

packages="packages/common packages/backend packages/fastify packages/sveltekit packages/frontend"
for dir in $packages; do
    echo "Building $dir..."
    (cd $dir; pnpm build)
done
