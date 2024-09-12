#!/bin/bash

for dir in packages/*; do
    echo "Publishing $dir..."
    (cd $dir; pnpm publish)
done
