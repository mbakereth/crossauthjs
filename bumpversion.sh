#!/bin/bash
version1=`cat VERSION | awk -F. '{print $1}'`
version2=`cat VERSION | awk -F. '{print $2}'`
version3=`cat VERSION | awk -F. '{print $3}'`

if [ $# = 0 ]; then
    echo "bumpversion.txt 1|2|3"
    echo "1 = major version"
    echo "2 = minor version"
    echo "3 = bug fix"
    exit 0
fi
if [ $1 == 1 ]; then
    version1=`expr $version1 + 1`
    version2=0
    version3=0
elif [ $1 == 2 ]; then
    version2=`expr $version2 + 1`
    version3=0
else
    version3=`expr $version3 + 1`
fi

echo "$version1.$version2.$version3" > VERSION


for file in `ls packages/*/package.json examples/*/package.json`; do
    echo "Settng version in $file to $version1.$version2.$version3..."
    sed -E -i "" "s/\"version\": \"[0-9]+\.[0-9]+\.[0-9]+\"/\"version\": \"$version1\.$version2\.$version3\"/" $file 
done

