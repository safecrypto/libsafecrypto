#!/bin/bash

GNU_INDENT_RULES="-nbad -bap -nbbo -nbc -br -brs -c33 -cd33 -ncdb -ce -ci4 -cli0 -cp33 -cs -d0 -di1 -nfc1 -nfca -hnl -i4 -ip0 -l75 -lp -nut -npcs -nprs -npsl -saf -sai -saw -nsc -nsob -nss"

GREETING="Applying SAFEcrypto code styling ..."
echo $GREETING

# Find all .c and .h files and apply the code formatting rules. Exclude the
# third_party directory. The sha2.c macros cause problems for GNU indent,
# and it can be assumed that the third party software is formatted to the
# author's satisfaction.
for i in `find $1/$2 -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.py' -o -name '*.cs' -o -path src/utils/third_party -prune` ; \
    do indent $GNU_INDENT_RULES $i -o $i ; echo $i ;  done

echo "... code styling complete"
