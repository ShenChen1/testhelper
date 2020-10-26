#!/bin/bash
set -eu

while [[ "$#" > 0 ]] ; do
	echo ">>> $1:"

	while read line; do
		echo "${line% *}"
		echo "${line##* }" | base64 -d
		echo ""
	done < "$1"

	echo ""
	shift
done
