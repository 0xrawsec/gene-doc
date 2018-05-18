#!/bin/bash

source="./source"

buildid=$(find "$source" -type f -printf "%T+ %p\n"| md5sum | cut -d ' ' -f 1)

while [ true ]
do
    newbuildid=$(find "$source" -type f -printf "%T+ %p\n" | md5sum | cut -d ' ' -f 1)
    if [[ $buildid != $newbuildid ]]
    then
        echo [$(date -I"seconds")] "Change detected: generation new documentation"
        make html
        buildid=$newbuildid
    fi
    sleep 1
done
