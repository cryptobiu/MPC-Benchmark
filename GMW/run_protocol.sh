#! /bin/bash
for i in `seq ${1} 1 ${2}`;
do
        ./GMW -partyID $i -circuitFile $3 -partiesFile $4 -inputFile AesInputs$i.txt -numThreads $5 -internalIterationsNumber $6 &
        echo "Running $i..."
done

