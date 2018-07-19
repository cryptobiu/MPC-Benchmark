#! /bin/bash
for i in `seq 0 1 $((${1}-1))`;
do
        ./GMW -partyID ${i} -circuitFileName ${2} -partiesFileName ${3} -inputfileName AesInputs${i}.txt -numThreads ${4} -repetitionId ${5} &
        echo "Running $i..."
done

