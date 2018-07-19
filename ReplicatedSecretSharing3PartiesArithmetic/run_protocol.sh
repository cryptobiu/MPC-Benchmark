#!/usr/bin/env bash

for i in `seq ${1} 1 ${2}`;
do
    ./ReplicatedSecretSharing3PartiesArithmetic -partyID ${i} -inputFile ${3} -outputFile output.txt \
     -circuitFile ${4} -fieldType ${5} -partiesFile ${6} -internalIterationsNumber ${7} &
    echo "Running $i..."
done
