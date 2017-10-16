#!/bin/bash

GREETING="Applying SAFEcrypto file information ..."
echo $GREETING

git_branch=$(git rev-parse --abbrev-ref HEAD) ;
for i in `find $1/$2 -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.cs' -o -name '*.py'` ; do
	path=${i#$1/}
	git_author=$(git log --pretty=format:"%cn <%ce>" -1 -- $path) ;
	git_date=$(git log --pretty=format:"%cd" -1 -- $path) ;
	git_id=$(git log --pretty=format:"%H" -1 -- $path);
	sed -i 's/\$SC_AUTHOR\$/'"$git_author"'/g' $i ;
	sed -i 's/\$SC_DATE\$/'"$git_date"'/g' $i ;
	sed -i 's/\$SC_BRANCH\$/'"$git_branch"'/g' $i ;
	sed -i 's/\$SC_IDENT\$/'"$git_id"'/g' $i ;
done

echo "... file information complete"
