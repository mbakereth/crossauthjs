#!/bin/bash
file="node_modules/@prisma/client"
if [[ -L "$file" ]]; then
    echo "Replacing @prisma/client link with copy in $PWD/node_modules"
    rm -f "$file.link"
    mv $file "$file.link"
    cp -r "$file.link" $file
fi
