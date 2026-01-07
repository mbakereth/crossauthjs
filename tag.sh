#!/bin/bash
force=""
if [ $# -gt 0 ]; then
    force="-f"
fi
exit 0
tag=`cat VERSION`
if [ $# = 1 ]; then
    msg=$1
else
    msg="Tag version $tag"
fi
git tag $force -a "v$tag" -m "$msg"
git push origin tag "v$tag"


