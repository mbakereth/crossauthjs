#!/bin/bash
file="node_modules/@prisma/client"
if [[ -d "$file" ]]; then
    echo "Removing @prisma/client $PWD/node_modules"
    #rm -f "$file"
fi
