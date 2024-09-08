#!/bin/bash

if [ $# = 0 ]; then
    echo "bumpversion.txt 1|2|3"
    echo "1 = major version"
    echo "2 = minor version"
    echo "3 = bug fix"
    exit 0
fi

bash ./bumpversion.sh $1
bash ./build.sh $1

git commit -a
git push

for dir in packages/*; do
    echo "Publishing $dir..."
    (cd $dir; pnpm publish)
done
