#!/bin/bash
make clean
bear make
REPORT=reports/clang-tidy-report
>$REPORT
echo "Report file is : [$REPORT]"
echo "Running clang-tidy : $(clang-tidy --version)"
clang_version=$(clang-tidy --version|grep version|awk '{print $3}')
if [[ $clang_version =~ ^"9.0" ]];
then
    echo "New version most checks, I'm happy"
    find . ! -name "*test*" \( -name "*.c"  \)  \( -exec echo FILE_NAME == {} \; -exec clang-tidy   -p .  -checks="$(cat clang-tidy-checks.txt)" {}  \;   \) >> $REPORT
else
    echo "Old version no checks, it's instable"
    find . ! -name "*test*" \( -name "*.c"  \)  \( -exec echo FILE_NAME == {} \; -exec clang-tidy   -p .  -checks="$(cat clang-tidy-checks_3.txt)" {}  \;   \) >> $REPORT
fi
num_warnings=$(grep "warning:" $REPORT |wc -l)
num_error=$(grep "error:" $REPORT |wc -l)
ls -l $REPORT
echo "Report file $REPORT with : warning [$num_warnings] and error [$num_error] "
#for file in $(find . ! -name "*test*" \( -name "*.c"  \) );
#do
#    echo "Analyze file :[$file]"
#    clang-tidy  -p .  -checks="$(cat clang-tidy-checks.txt)" "$file" >> $REPORT;
#done
