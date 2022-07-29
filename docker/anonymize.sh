#!/bin/bash

# enable bash strict mode
# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail
IFS=$'\n\t'

ANON="anonymized"
for var in "$@"; do
	echo "Replacing the following matches of $var in files:"
	grep -r "$var" .
	find . -type f -print0 | xargs -0 -n1 sed -i "s/$var/$ANON/g"
	echo ""

	echo "Replacing the following matches of $var in filenames:"
	find . -name "*$var*" | while read FILE
	do
		NEWFILE="$(echo $FILE | sed "s/$var/$ANON/g")"
		echo "$FILE -> $NEWFILE"
		mv "$FILE" "$NEWFILE"
	done
	echo ""

	ANON="${ANON}d"  # make sure every keyword is anonymized differently
done
