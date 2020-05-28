#!/bin/bash
echo "##########################################"
echo "### START Running Coverage    ############"
echo "##########################################"
make clean
COVERAGE_FLAGS=--coverage make
make test

GCOV=gcov 
BASE_DIR=$(pwd)
REPORT=./reports/coverage
REPORT_GCOV=$REPORT.gcov
REPORT_XML=$REPORT.xml
REPORT_TMP=$REPORT._$$
>$BASE_DIR/$REPORT_GCOV
>$BASE_DIR/$REPORT_XML

echo "Report file is : [$REPORT]"
gcov -v
for dir in $(find . -name "pcep_*" -type d)
do 
    cd $dir
        for src in $(find . -name "*.c" 2>/dev/null)
        do
            case $src in
                ./src*)
                    #As src are generated in obj
                    $GCOV $(echo $src |sed 's/src/obj/g')
                    ;;
                ./test*)
                    $GCOV  $src
                    ;;
            esac
        done
        #Paste in one file
        set -x
        cat *gcov |sed  "s|Source:|&$dir/|" >> $BASE_DIR/$REPORT_GCOV
        set +x
    cd -
done

# Generate the xml format that sonar-cxx plugin accepts.
gcovr  -x -r . --object-directory=$BASE_DIR/$REPORT_GCOV -o $BASE_DIR/$REPORT_TMP
# As *.o are generated in obj dir must chage to sonar-cxx parse ok
cat $BASE_DIR/$REPORT_TMP |sed 's|/obj/|/src/|g' > $BASE_DIR/$REPORT_XML
rm $BASE_DIR/$REPORT_TMP




echo "##########################################"
echo "### END Running Coverage    ##############"
echo "##########################################"
