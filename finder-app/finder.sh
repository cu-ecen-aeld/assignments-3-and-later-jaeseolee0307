#!/bin/sh

if [ "$#" -ne 2 ]; then
    echo "Error: No argument of the directory path and the search string."
    exit 1
fi

filesdir="$1"
searchstr="$2"

if [ ! -d "$filesdir" ]; then
    echo "Error: '$filesdir' is not a directory on the filesystem"
    exit 1
fi

file_count=$(find "$filesdir" -type f | wc -l)
matching_lines=$(grep -r "$searchstr" "$filesdir" | wc -l)

echo "The number of files are $file_count and the number of matching lines are $matching_lines"
