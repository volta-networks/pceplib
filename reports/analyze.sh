#!/bin/bash
echo "##########################################"
echo "### START Running Analysis    ############"
echo "##########################################"
#set -x#Uncomment to debug
make clean
bear make
REPORT=./reports/clang-tidy-report
>$REPORT
echo "Report file is : [$REPORT]"
echo "Guessing which clang-tidy version we have"
which clang-tidy >/dev/null && export CLANG_TIDY_PROGRAM=clang-tidy
which clang-tidy-7 >/dev/null && export CLANG_TIDY_PROGRAM=clang-tidy-7
which clang-tidy-8 >/dev/null && export CLANG_TIDY_PROGRAM=clang-tidy-8
which clang-tidy-9 >/dev/null && export CLANG_TIDY_PROGRAM=clang-tidy-9
if [ ! -z $CLANG_TIDY_PROGRAM ]
then
    echo "Running clang-tidy : $( $CLANG_TIDY_PROGRAM --version)"
    clang_version=$($CLANG_TIDY_PROGRAM --version|grep version|awk '{print $3}'|awk -F. '{print $1}')
    echo "Version found $clang_version"
    if [ $(($clang_version)) -le 6 ]
    then
        echo "Old version no checks, version 3 it's unstable"
        find . ! -name "*test*" \( -name "*.c"  \)  -exec $CLANG_TIDY_PROGRAM   -p .  -checks="$(cat clang-tidy-checks_3.txt)" {}  \;    >> $REPORT
    else
        if [ $clang_version -ge 7 ]
        then
            echo "New version most checks, I'm happy"
            find . ! -name "*test*" \( -name "*.c"  \)  -exec $CLANG_TIDY_PROGRAM   -p .  -checks="$(cat clang-tidy-checks.txt)" {} -- $(cat .clang_tidy)  \;  >> $REPORT
        fi
    fi
else
    echo "##########################################"
    echo "### NO clang-tidy installed ##############"
    echo "##########################################"
fi




num_warnings=$(grep -c "warning:" $REPORT )
num_error=$(grep -c "error:" $REPORT )
ls -l $REPORT
echo "Report file $REPORT with : warning [$num_warnings] and error [$num_error] "
echo "##########################################"
echo "### END Running Analysis    ##############"
echo "##########################################"
